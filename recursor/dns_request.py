from enum import Enum
import ipaddress
import socket
import typing as tp


def send(domain: str, ip: str):
    request = compose_request(domain=domain, rd=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(request, (ip, 53))
        response = Response(sock.recvfrom(4096)[0])
    if not response.parse():
        return None
    return response


def compose_request(domain: str, request_id=0, rd=False) -> bytes:
    request_components = bytearray()
    request_components.extend(request_id.to_bytes(2, byteorder='big', signed=False))

    flags = 0
    flags |= int(rd) << 8

    request_components.extend(flags.to_bytes(2, byteorder='big', signed=False))

    questions = 1
    request_components.extend(questions.to_bytes(2, byteorder='big', signed=False))
    zero = 0
    request_components.extend(zero.to_bytes(6, byteorder='big', signed=False))

    domain_parts = domain.split(".")
    if not domain_parts[-1]:
        domain_parts.pop()

    for part in domain_parts:
        if len(part) > 63:
            raise OverflowError
        request_components.extend(len(part).to_bytes(1, byteorder='big', signed=False))
        request_components.extend(bytes(part, encoding="ascii"))
    request_components.extend(zero.to_bytes(1, byteorder='big', signed=False))

    type_or_class = 1
    request_components.extend(type_or_class.to_bytes(2, byteorder='big', signed=False))
    request_components.extend(type_or_class.to_bytes(2, byteorder='big', signed=False))
    return bytes(request_components)


class Record:
    def __init__(self, response: bytes, domain: str):
        self.response = response
        self.domain = domain.lower()
        self.rr_type: int = 0
        self.ttl: int = 0
        self.ip: str = ""

    def parse_after_name(self, offset: int) -> int:
        bytes_handled = 0
        self.rr_type = int.from_bytes(self.response[offset + bytes_handled:offset + bytes_handled + 2], 'big')
        assert int.from_bytes(self.response[offset + bytes_handled + 2:offset + bytes_handled + 4], 'big') == 1
        bytes_handled += 4  # skip class because it is IN
        self.ttl = int.from_bytes(self.response[offset + bytes_handled:offset + bytes_handled + 4], 'big')
        bytes_handled += 4
        rd_length = int.from_bytes(self.response[offset + bytes_handled:offset + bytes_handled + 2], 'big')
        bytes_handled += 2
        rdata = self.response[offset + bytes_handled:offset + bytes_handled + rd_length]
        if self.rr_type == 1:
            assert len(rdata) == 4
            self.ip = str(ipaddress.ip_address(int.from_bytes(rdata, 'big')))
            bytes_handled += 4
        elif self.rr_type == 2:
            self.domain, handled = parse_name(self.response, offset + bytes_handled)
            assert handled == rd_length
            bytes_handled += handled
        elif self.rr_type == 28:
            assert len(rdata) == 16
            self.ip = str(ipaddress.ip_address(int.from_bytes(rdata, 'big')))
            bytes_handled += 16
        else:
            bytes_handled += len(rdata)
        return bytes_handled


class Response:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.id: int = 0
        self.qr: bool = False
        self.opcode: int = 0
        self.aa: bool = False
        self.tc: bool = False
        self.rd: bool = False
        self.ra: bool = False
        self.z: int = 0
        self.r_code: int = 0
        self.an_count: int = 0
        self.ns_count: int = 0
        self.ar_count: int = 0

        self.a_records: tp.List[Record] = []
        self.ns_records: tp.List[Record] = []
        self.aaaa_records: tp.List[Record] = []

    def parse(self) -> bool:
        self.id = int.from_bytes(self.response[:2], 'big')
        block = int.from_bytes(self.response[2:4], 'big')
        self.qr = bool(block >> 15)
        self.opcode = 0xF & (block >> 11)
        self.aa = bool(1 & (block >> 10))
        self.tc = bool(1 & (block >> 9))
        self.rd = bool(1 & (block >> 8))
        self.ra = bool(1 & (block >> 7))
        self.z = 0xF & (block >> 3)
        self.r_code = 0xF & block

        self.an_count = int.from_bytes(self.response[6:8], 'big')
        self.ns_count = int.from_bytes(self.response[8:10], 'big')
        self.ar_count = int.from_bytes(self.response[10:12], 'big')

        if self.aa and self.r_code == 3:
            return False

        offset = 12
        domain, bytes_handled = self._parse_request(offset)
        offset += bytes_handled
        for i in range(self.an_count + self.ns_count + self.ar_count):
            record, bytes_handled = self._parse_record(offset)
            offset += bytes_handled
            if record.rr_type == 1:
                self.a_records.append(record)
            elif record.rr_type == 2:
                self.ns_records.append(record)
            elif record.rr_type == 28:
                self.aaaa_records.append(record)
        return True

    def _parse_request(self, offset: int) -> (str, int):
        domain, bytes_handled = parse_name(self.response, offset)
        return domain, bytes_handled + 4  # also IN A

    def _parse_record(self, offset: int) -> (Record, int):
        name, bytes_handled = parse_name(self.response, offset)
        record = Record(response=self.response, domain=name)
        bytes_handled += record.parse_after_name(offset + bytes_handled)
        return record, bytes_handled


def parse_name(response: bytes, offset: int) -> (str, int):
    bytes_handled = 0
    add_bytes_for_name = True
    name = ""
    while True:
        name_len = int.from_bytes(response[offset:offset + 1], 'big')
        if (name_len & 0xC0) == 0xC0:
            # compressed name
            offset = int.from_bytes(response[offset:offset + 2], 'big')
            offset ^= 0xC000
            if add_bytes_for_name:
                bytes_handled += 2
            add_bytes_for_name = False
            continue
        else:
            offset += 1
            if add_bytes_for_name:
                bytes_handled += 1
        if not name_len:
            break
        name += f"{response[offset:offset + name_len].decode(encoding='ascii')}."
        offset += name_len
        if add_bytes_for_name:
            bytes_handled += name_len
    return name.lower(), bytes_handled
