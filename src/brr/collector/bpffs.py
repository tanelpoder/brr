from __future__ import annotations

import errno
import os
from pathlib import Path

from brr.collector.syscall import SyscallBpfCollector


class BpffsScanner:
    def __init__(self, root: str = "/sys/fs/bpf") -> None:
        self.root = Path(root)

    def is_available(self) -> bool:
        return self.root.exists() and self.root.is_dir()

    def scan_pinned_paths(
        self,
        collector: SyscallBpfCollector,
    ) -> dict[str, dict[int, tuple[str, ...]]]:
        pinned: dict[str, dict[int, list[str]]] = {
            "program": {},
            "map": {},
            "link": {},
            "btf": {},
        }
        if not self.is_available():
            return {kind: {} for kind in pinned}

        for path in self.root.rglob("*"):
            if path.is_dir():
                continue
            record = self._read_pinned_object(path, collector)
            if record is None:
                continue
            kind, object_id = record
            pinned[kind].setdefault(object_id, []).append(str(path))

        return {
            kind: {object_id: tuple(sorted(paths)) for object_id, paths in values.items()}
            for kind, values in pinned.items()
        }

    def _read_pinned_object(
        self,
        path: Path,
        collector: SyscallBpfCollector,
    ) -> tuple[str, int] | None:
        try:
            fd = collector.open_pinned_path(str(path))
        except OSError as exc:
            if exc.errno in {
                errno.EACCES,
                errno.ENOENT,
                errno.ENOTDIR,
                errno.EINVAL,
                errno.EBADF,
            }:
                return None
            raise

        try:
            return collector.classify_pinned_fd(fd)
        finally:
            os.close(fd)
