"""In-memory host-list repositories.

These load newline-separated host lists from data files once at startup into a
``frozenset[str]`` so lookups are O(1) and the files are not re-read per
request. Normalization (lowercase, trailing-dot stripping, comment/blank
handling) is applied at load time.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from pathlib import Path
from typing import TypeVar

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"

_SuffixHostRepositoryT = TypeVar("_SuffixHostRepositoryT", bound="SuffixHostRepository")


def _normalize_host(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Strip a single trailing root dot, lowercase.
    if line.endswith("."):
        line = line[:-1]
    line = line.lower()
    if not line:
        return None
    return line


class HostListRepository:
    """Holds a frozen set of normalized hostnames loaded from a data file."""

    def __init__(self, hosts: Iterable[str]) -> None:
        self._hosts: frozenset[str] = frozenset(hosts)

    @classmethod
    def from_file(cls, relative_path: str) -> HostListRepository:
        """Load a host list, preferring ``data/`` then the project root.

        All datasets, including ``disposable_hosts.txt``, live under ``data/``.
        Resolving relative to the package keeps loading independent of the
        process working directory.
        """
        data_path = DATA_DIR / relative_path
        if data_path.exists():
            return cls.from_path(data_path)
        root_path = PROJECT_ROOT / relative_path
        if root_path.exists():
            return cls.from_path(root_path)
        raise FileNotFoundError(f"host list not found: {relative_path}")

    @classmethod
    def from_path(cls, path: Path) -> HostListRepository:
        hosts: set[str] = set()
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                normalized = _normalize_host(raw)
                if normalized:
                    hosts.add(normalized)
        return cls(hosts)

    def __contains__(self, host: str) -> bool:
        return host.lower() in self._hosts

    def __len__(self) -> int:
        return len(self._hosts)

    def as_set(self) -> frozenset[str]:
        return self._hosts


class SuffixHostRepository:
    """Repository over a host list using exact and subdomain/suffix matching.

    A registered host matches itself exactly and every subdomain of it, so a
    single ``example.com`` entry also flags ``sub.example.com``. This is shared
    by lists (e.g. disposable, malicious) whose membership should cascade down
    the label chain.
    """

    def __init__(self, hosts: Iterable[str]) -> None:
        self._hosts: frozenset[str] = frozenset(hosts)
        self._lock = threading.Lock()

    @classmethod
    def from_file(
        cls: type[_SuffixHostRepositoryT], relative_path: str
    ) -> _SuffixHostRepositoryT:
        """Load a suffix-matched host list, preferring ``data/`` then the root."""
        data_path = DATA_DIR / relative_path
        if data_path.exists():
            return cls.from_path(data_path)
        root_path = PROJECT_ROOT / relative_path
        if root_path.exists():
            return cls.from_path(root_path)
        raise FileNotFoundError(f"host list not found: {relative_path}")

    @classmethod
    def from_path(cls: type[_SuffixHostRepositoryT], path: Path) -> _SuffixHostRepositoryT:
        hosts: set[str] = set()
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                normalized = _normalize_host(raw)
                if normalized:
                    hosts.add(normalized)
        return cls(hosts)

    def __contains__(self, host: str) -> bool:
        return self.matches(host)

    def matches(self, host: str) -> bool:
        """Return True if the host (or one of its subdomains) is listed.

        Exact match first, then suffix matching so that any subdomain of a
        registered host is also treated as present (e.g. ``sub.example.com``
        when ``example.com`` is listed).
        """
        normalized = host.lower().rstrip(".")
        if normalized in self._hosts:
            return True
        # Suffix matching: walk the label chain.
        labels = normalized.split(".")
        for i in range(1, len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in self._hosts:
                return True
        return False

    def as_set(self) -> frozenset[str]:
        return self._hosts


class DisposableEmailRepository(SuffixHostRepository):
    """Repository over the disposable-hosts data file.

    Supports both exact-match and subdomain/suffix matching. Matching is
    decided by the caller via :meth:`is_disposable`.
    """

    @classmethod
    def from_file(cls, relative_path: str = "disposable_hosts.txt") -> DisposableEmailRepository:
        """Load a disposable-host list, preferring ``data/`` then the project root."""
        data_path = DATA_DIR / relative_path
        if data_path.exists():
            return cls.from_path(data_path)
        root_path = PROJECT_ROOT / relative_path
        if root_path.exists():
            return cls.from_path(root_path)
        raise FileNotFoundError(f"disposable host list not found: {relative_path}")

    def is_disposable(self, host: str) -> bool:
        """Return True if the host is a known disposable domain.

        Exact match first, then suffix matching so that any subdomain of a
        registered disposable host is also treated as disposable (e.g.
        ``sub.mail.example.com`` when ``mail.example.com`` is listed).
        """
        return self.matches(host)


class MaliciousHostRepository(SuffixHostRepository):
    """Repository over the malicious-hosts blocklist data file.

    Matches exact hosts and any of their subdomains via suffix matching, so a
    listed ``evil.example.com`` also matches ``sub.evil.example.com``.
    """

    @classmethod
    def from_file(cls, relative_path: str = "malicious_hosts.txt") -> MaliciousHostRepository:
        """Load a malicious-host list, preferring ``data/`` then the project root."""
        data_path = DATA_DIR / relative_path
        if data_path.exists():
            return cls.from_path(data_path)
        root_path = PROJECT_ROOT / relative_path
        if root_path.exists():
            return cls.from_path(root_path)
        raise FileNotFoundError(f"malicious host list not found: {relative_path}")

    def is_malicious(self, host: str) -> bool:
        """Return True if the host (or a subdomain) is on the blocklist."""
        return self.matches(host)
