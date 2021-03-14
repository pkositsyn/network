from collections import abc
from collections import OrderedDict
from dataclasses import dataclass
import time
import typing as tp


@dataclass
class Record:
    deadline: float
    ips: tp.List[str]


class Cache(abc.MutableMapping):
    """Cache is LRU cache, managing ttl"""

    def __init__(self, capacity: int) -> None:
        self.storage = OrderedDict()
        self.capacity = capacity

    def __setitem__(self, k: str, v: Record) -> None:
        if k in self.storage:
            self.storage.move_to_end(k)
        elif len(self.storage) == self.capacity:
            self.storage.popitem(last=False)
        self.storage[k] = v

    def __delitem__(self, k: str) -> None:
        self.storage.pop(k)

    def __getitem__(self, k: str) -> Record:
        record = self.storage[k]
        if record.deadline < time.time():
            self.storage.pop(k)
        self.storage.move_to_end(k)
        return record

    def __len__(self) -> int:
        return len(self.storage)

    def __iter__(self) -> tp.Iterator[Record]:
        return self.storage
