# Correctness validation against perf

This document describes a July 2026 comparison of brr with Linux `perf` while
libbpf-tools `biolatency` traced a sustained NVMe random-read workload. The
goal was to validate sample transport, BPF program attribution, source
hotspots, helper callchains, and activity counters against independent kernel
interfaces.

## Test setup

- Linux 6.17 on four CPUs with the BPF JIT enabled.
- Eight fio processes using `psync`, queue depth 1, 4 KiB random O_DIRECT reads
  against one populated 8 GiB file on `/dev/nvme0n1`.
- About 94,400 read IOPS with the device continuously utilized.
- One `biolatency -TQDF 5` process kept its block request issue and completion
  programs loaded throughout every capture.
- brr commit `07b2b79`.

The test used isolated captures in ABBA order and captures where brr and perf
sampled the same event concurrently. Reversing which collector started first
checked for launch-order bias. Direct profiles used `cycles:k` at 9,997 Hz for
30 seconds; callchain profiles used 4,999 Hz for 30 seconds. `cpu-clock:k` at
997 Hz was retained as a sample-transport control.

Perf must use a kernel-only event to match brr. A plain `cycles` event includes
user-space samples and is not a like-for-like comparison.

Representative commands:

```bash
fio --name=prepare --filename=/nvme/brr-validation.dat --size=8G \
    --rw=write --bs=1M --ioengine=psync --direct=1 --end_fsync=1

sudo biolatency -TQDF 5 > biolatency.txt &
biolatency_pid=$!

fio --name=read-load --filename=/nvme/brr-validation.dat --size=8G \
    --rw=randread --bs=4k --ioengine=psync --direct=1 --iodepth=1 \
    --numjobs=8 --thread=0 --time_based --runtime=300 --norandommap \
    > fio.txt &
fio_pid=$!
sleep 10

sudo brr profile --event cycles -F 9997 --duration 30 \
    --limit 0 --line-limit 0 --json --fail-on-loss > brr.json &
brr_pid=$!
sudo perf record -a -e cycles:k -F 9997 -m 128 \
    -o perf.data -- sleep 30 &
perf_pid=$!
wait "$brr_pid" "$perf_pid"

sudo perf report -i perf.data --stdio --show-nr-samples --no-children
sudo perf script -i perf.data --ns \
    -F comm,pid,tid,cpu,time,event,ip,sym,symoff,dso,period,srcline

kill -INT "$fio_pid"
sudo kill -INT "$biolatency_pid"
rm -f /nvme/brr-validation.dat
```

For repeated brr testing, the repository includes a wrapper for the same fio
and biolatency workload. Its first argument sets the number of fio process jobs
and its second sets the runtime in seconds:

```bash
./run_fio_and_biolatency.sh 8 300
```

The script prepares `/nvme/brr-validation.dat` at 8 GiB when it does not yet
exist, retains it for subsequent runs, and writes `fio.txt` and
`biolatency.txt` in the current directory. `FIO_FILE`, `FIO_SIZE`, `FIO_LOG`,
and `BIOLATENCY_LOG` may be set to override those paths or the preparation
size. It authenticates with sudo before starting biolatency in the background
and stops both workloads if the script is interrupted.

For helper attribution, add `--kernel-samples --call-graph fp` to brr and
`-g --call-graph fp` to `perf record`.

## Results

Every brr capture reported zero lost samples, zero throttling, zero malformed
records, zero discarded bytes, 100% perf running time, and
`incomplete=false`. All ten perf captures reported zero lost samples. Direct
ring occupancy remained below 27%; callchain occupancy remained below 28% even
when the automatic callchain ring was capped at 128 pages per CPU by
`perf_event_mlock_kb`.

The simultaneous cycles captures produced the closest controlled comparison:

| Metric | Perf started first | brr started first |
|---|---:|---:|
| Total sample-count difference | 0.03% | 0.29% |
| Issue-program share difference | 0.31% | 0.37% |
| Completion-program share difference | 1.03% | 0.91% |
| Dominant issue source-line difference | 4.03% | 6.48% |
| Dominant completion source-line difference | 2.81% | 0.43% |

The same BPF programs ranked first in both collectors, with identical top-three
source-line membership. Lower-count secondary lines varied more, as expected
from two independent statistical sample streams, but their confidence
intervals overlapped and there was no directional bias.

In the simultaneous callchain capture, brr collected 541,888 samples and perf
collected 541,806, a 0.015% difference. Normalized attribution differences
were:

| Program | Direct BPF | Kernel/helper attributed |
|---|---:|---:|
| Block request issue | 3.99% | 2.50% |
| Block request completion | 3.58% | 0.16% |

Helper rankings also agreed. Both collectors identified time in TSC reads,
BPF hash-table lookup/update and locking, per-CPU freelists, and probe reads,
with the dominant concurrent helper shares generally differing by only a few
percent.

The activity counter provided a non-sampling cross-check. During one 20-second
interval, brr reported 1,929,645 issue executions and 1,929,643 completion
executions. The aligned biolatency histogram bins contained 1,930,485 NVMe
completions, a 0.044% difference. The block device's exact read-completion
delta differed by 0.66%, consistent with command-boundary skew and background
I/O.

## Interpretation

The comparison supports these conclusions:

- brr's perf ring consumption and BPF JIT range attribution agree with perf.
- Program shares, meaningful source hotspots, and BPF-to-helper callchain
  attribution are precise enough for diagnostic profiling.
- Simultaneous captures or repeated averages are preferable for validation.
  Individual adjacent windows showed substantial real path variation despite
  stable aggregate IOPS.
- The default 997 Hz cpu-clock profile is useful for low-overhead sampling but
  produced only single-digit BPF samples per window for these sub-microsecond
  programs. It cannot provide a statistically stable line ranking in that
  case.
- A direct profile excludes time whose current instruction is in a BPF helper
  or another kernel function. Use `--kernel-samples` for inclusive attribution.

## Current limitations

- The kernel exposes BPF object names to brr with the usual 15-character
  truncation. Perf additionally synthesizes names for BPF subprograms such as
  `handle_block_rq_complete`; brr currently reports their source lines but not
  those subprogram function names.
- The distro bpftool used for this test was built without JIT disassembly
  support. Its translated `linum` output independently confirmed source files,
  lines, columns, and text. Perf's raw JIT IPs were mapped using the JIT line
  boundaries returned by the kernel to brr, so the test validates sample
  counting and line aggregation but is not a second implementation of the
  kernel JIT-line-address parser.
