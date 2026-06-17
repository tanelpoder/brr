from __future__ import annotations

from brr.collector.bpffs import BpffsScanner
from brr.collector.service import BpfSnapshotService
from brr.collector.syscall import SyscallBpfCollector


def build_snapshot_service(bpffs: str = "/sys/fs/bpf") -> BpfSnapshotService:
    return BpfSnapshotService(
        collector=SyscallBpfCollector(),
        bpffs_scanner=BpffsScanner(bpffs),
    )
