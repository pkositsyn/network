from aiohttp import web
import time
import typing as tp

import cache
import dns_request


async def handler(request: web.Request) -> web.Response:
    domain = request.query.get("domain").lower()
    if not domain or not valid(domain):
        return web.json_response(text="Domain must be specified and valid", status=404)

    do_trace = request.query.get("trace") is not None
    writer = ResponseWriter(do_trace)

    addresses = None
    if not do_trace:
        addresses = request.app['cache'].get(domain)

    if addresses is None:
        addresses = await find_recursive(domain, root_dns_servers, writer)
        if addresses is not None:
            request.app['cache'][domain] = addresses

    if addresses is None:
        writer.write_forced("Couldn't find ip for domain")
        return web.json_response(text=writer.result(), status=404)
    writer.write("")
    writer.write_forced("\n".join(map(lambda ip: f"{ip} {domain}", addresses.ips)))
    return web.json_response(text=writer.result())


async def find_recursive(domain: str, dns_servers: tp.Dict[str, str], writer) -> tp.Optional[cache.Record]:
    for server_domain, host in dns_servers.items():
        writer.write(f"{host} {server_domain}")
        response = dns_request.send(domain, host)
        if not response:
            continue

        if response.aa:
            ips = []
            ttl = 0
            for record in response.a_records:
                if record.domain.startswith(domain):
                    ips.append(str(record.ip))
                    ttl = record.ttl
            if not ips:
                return None
            return cache.Record(deadline=time.time() + ttl, ips=ips)

        new_domains = [record.domain for record in response.ns_records]
        new_servers = {}
        for a_record in response.a_records:
            if a_record.domain not in new_domains:
                continue
            new_servers[a_record.domain] = a_record.ip
        if not new_servers:
            if new_domains:
                # try to find domains recursively
                writer.write("")
                result = await find_recursive(new_domains[0], root_dns_servers, writer)
                if result:
                    dns_servers = {}
                    for ip in result.ips:
                        dns_servers[new_domains[0]] = ip
                    writer.write("")
                    return await find_recursive(domain, dns_servers, writer)
            continue
        writer.write("")
        return await find_recursive(domain, new_servers, writer)
    return None


def valid(domain: str) -> bool:
    for ch in domain:
        if not (ch.isalnum() or ch in ".-"):
            return False
    labels = domain.split(".")
    if not labels[-1]:
        labels.pop()
    for label in labels:
        if not label or label.startswith((".", "-")):
            return False
    return True


class ResponseWriter:
    def __init__(self, do_trace=False):
        self.do_trace = do_trace
        self.parts = []

    def write(self, data: str):
        if self.do_trace:
            self.parts.append(data)

    def write_forced(self, data: str):
        self.parts.append(data)

    def result(self):
        return "\n".join(self.parts)


root_dns_servers = {
    "a.root-servers.net": '198.41.0.4',
    "b.root-servers.net": '199.9.14.201',
    "c.root-servers.net": '192.33.4.12',
    "d.root-servers.net": '199.7.91.13',
    "e.root-servers.net": '192.203.230.10',
    "f.root-servers.net": '192.5.5.241',
    "g.root-servers.net": '192.112.36.4',
    "h.root-servers.net": '198.97.190.53',
    "i.root-servers.net": '192.36.148.17',
    "j.root-servers.net": '192.58.128.30',
    "k.root-servers.net": '193.0.14.129',
    "l.root-servers.net": '199.7.83.42',
    "m.root-servers.net": '202.12.27.33',
}
