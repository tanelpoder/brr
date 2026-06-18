# eBPF Runtime Reporter and Profiler - brr

**`brr`** is an eBPF program Runtime Reporter _and_ Profiler.

Since eBPF programs are pieces of machine code residing in (kernel) address space, you can profile them with standard `perf` just like any other kernel function. However, perf alone won't show you other useful metrics like number of executions and average eBPF program runtime, like [bpftop](https://github.com/jfernandez/bpftop) does. Also, I want an easy way to map CPU samples to original source code lines, where possible.

I wanted to unify both approaches, display the bpftop-style call count & probe latency, with the ability to drill down into where _inside_ the eBPF program most of the time is spent. This tool is not calling the `perf` command under the hood, but uses `perf_event_open()` API directly. Also, it uses the `bpf()` syscall, for things like enabling eBPF program stats accounting (BPF\_ENABLE\_STATS) while `brr` is running. 

I built this for my own use, but this tool/idea may be useful for others too. It's entirely AI-coded by Codex in Python using my specs & tests. It's good enough for my [performance testing](https://tanelpoder.com/posts/optimizing-ebpf-biolatency-accounting/) environments (not so sure about production).

1. [Jump to Installation section](#install)
1. [Jump to command line options](#command-line-options)


## Usage

`brr` runs in two modes, **`brr top`** is an interactive TUI and other options like **`brr activity`**, **`brr profile`** produce profiles in plain text output (including JSON, CSV). See [EXAMPLE\_OUTPUT.md](EXAMPLE_OUTPUT.md) for text mode profiling examples.

Here are some screenshots from running `brr top` on a machine with some sysbench & fio stress-test workloads, while multiple different eBPF monitoring/observability programs were enabled.

The landing page shows the bpftop-style program execution summary. You can press "h" to display the help menu.

![](docs/images/brr-top-entrypoint-trimmed.png)

I had configured my `xcapture` tool to monitor all system calls of all threads in an efficient way (tracking + sampling, not tracing), we are apparently doing 2M syscalls/s on this machine and the `xcap_sys_enter` probe used 25% of _one CPU_ time in aggregate.

Now you can use arrow keys to navigate to the program of interest and press enter to see its source code snippets (coming from each program's BTF info if available). 

I picked the `get_tasks` program as it's a longer and more complex program. It's an eBPF task iterator doing _passive sampling_ of all system threads' states, without injecting any tracepoints or probes into their critical path.

![](docs/images/ebpf-task-local-storage.png)

In the image above, you see a column WEIGHT, this is just the number of perf CPU samples that fell into that specific code line.

You also see that some code lines have a little "+" sign in front of them. These are the CPU samples where we happened to be in some Linux _kernel_ function (not our eBPF program) - but that kernel function call was done by our eBPF program. You can press "e" to expand (and "c" to collapse) just like in perf to see the deeper stack under that eBPF program line.

So basically, I'm doing something like `perf record -g --call-graph ...` here, whenever I see a CPU sample in kernel function, I walk up the call-graph and see if the parent (or grandparent) function is our eBPF program of interest. eBPF programs can call (or fall) into Linux built-in kernel functions, as there are eBPF helper functions and other system activity like interrupts, page faults, spinlock gets, etc.

Here's an example with a `lock_xadd()` function call immediately catching (my) eyes:

![](docs/images/ebpf-lock-add-tsc-collapsed.png)

But when I expand the profile with "e", I see it's actually another function call `bpf_ktime_get_ns()` passed into the `lock_xadd(...)` as an argument that calls `read_tsc()` that takes most of the time under the original function call:

![](docs/images/ebpf-lock-add-tsc-expanded.png)

Here are two examples from the `syscount` command (part of bcc-tools) when running lots of syscalls concurrently:

![](docs/images/ebpf-hashtable-collapsed.png)

When expanded, we see that most of the samples fall under `__pi_memcpy` Linux kernel function:

![](docs/images/ebpf-hashtable-expanded.png)

When updating shared eBPF hash-maps under high concurrency (lots of events & lots of CPUs), then you might start seeing various "lock" functions showing up:

![](docs/images/ebpf-hashtable-lock-bucket.png)

With modern eBPF _sleepable_ programs (that allow reading other processes memory), you might even start seeing kernel spin lock functions and page fault handlers showing up in your profiles:

![](docs/images/ebpf-spinlock.png)

You can also press "e" on the folded/hidden lines showing `"..."` to expand the full source code (even without profile sample hits). Note that this source display is rendered from the actual binary representation, not the original source code file (compiler, JIT can move things around). So you may see weird source line ordering in the full program display.


## Install

### From Python source with uv

Requires Linux, Python 3.11 or newer, and **uv** package manager. The install instructions for uv [are here](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone https://github.com/tanelpoder/brr.git
cd brr
uv sync
sudo env PATH="$PATH" uv run brr
```

To build a self-contained single binary `brr` that you can run without `uv`:

```bash
uv tool install .
sudo env PATH="$PATH" brr
```

Once you have the `brr` file, it's just like any other binary, you can copy and run it from any directory you like. The env tricks are not needed when you put the `brr` stand-alone binary to a directory that is in the PATH of sudo/root users (or just use fully qualified pathname when executing the program).


### Download Stand-alone binaries for ARM and X86

If you don't want to build from source and are happy to run binaries from random internet pages like this one, then you can download the latest standalone binary for your platform from the [releases](https://github.com/tanelpoder/brr/releases) page.

On x86:

```
curl https://github.com/tanelpoder/brr/releases/download/v0.4.1/brr-0.4.1-linux-x86_64 -o brr
chmod u+x brr
sudo ./brr
```

On ARM:

```
curl https://github.com/tanelpoder/brr/releases/download/v0.4.1/brr-0.4.1-linux-aarch64 -o brr
chmod u+x brr
sudo ./brr
```


### Install Debian or Ubuntu Packages

Download the DEB for your architecture from the GitHub release, then install it:

```bash
sudo dpkg -i brr_0.4.1-1_amd64.deb
```

On ARM64:

```bash
sudo dpkg -i brr_0.4.1-1_arm64.deb
```

### Install on Fedora, RHEL and RPM-compatible systems

Download the RPM for your architecture from the GitHub release, then install it:

```bash
sudo rpm -Uvh brr-0.4.1-1.x86_64.rpm
```

On AArch64:

```bash
sudo rpm -Uvh brr-0.4.1-1.aarch64.rpm
```

The packaged command installs as `/usr/bin/brr` and contains a standalone
binary. It does not depend on system Python.

## Command line options

Most useful commands need root or equivalent Linux capabilities because they
open BPF objects and CPU-wide perf events.


The `--help` option shows the key features and options at higher level. You can run `--help` also for subcommands to get more detail, like `brr top --help`.

```
$ sudo brr --help
usage: brr [-h] [--bpffs BPFFS] [--json] [--csv] [--pretty] [-x] [-c] [-V]
           {prog,activity,top,map,link,btf,perf-events,dump,dump-compare,profile} ...

eBPF Runtime Reporter and Profiler by Tanel Poder (tanelpoder.com).

positional arguments:
  {prog,activity,top,map,link,btf,perf-events,dump,dump-compare,profile}
    prog                List loaded eBPF programs.
    activity            Show eBPF program runtime deltas.
    top                 Show the live eBPF top TUI.
    map                 List loaded eBPF maps.
    link                List loaded eBPF links.
    btf                 List loaded BTF objects.
    perf-events         List brr-supported perf events openable on this host.
    dump                Dump translated instructions and source-line metadata for a program.
    dump-compare        Compare brr dump output with bpftool source-line metadata.
    profile             Profile BPF JIT execution with native perf_event_open sampling.

options:
  -h, --help            show this help message and exit
  --bpffs BPFFS         bpffs mount path used for pinned object enrichment.
  --json                Emit machine-readable JSON instead of text.
  --csv                 Emit machine-readable CSV instead of text.
  --pretty              Pretty-print JSON output. Requires --json.
  -x, --extended        Show extended TAG and PINNED columns in text output.
  -c, --cumulative      Show cumulative runtime metrics where available in text output.
  -V, --version         Show version number and exit.

```

Open the interactive top-style TUI:

```bash
sudo brr top
sudo brr top -x
sudo brr top -c
```

Inside `brr top`, press `x` to toggle extended columns and `c` to toggle
cumulative columns.

List loaded eBPF programs:

```bash
sudo brr
sudo brr prog
sudo brr -x
```

List other object types:

```bash
sudo brr map
sudo brr link
sudo brr btf
```

Include runtime counters in the program list:

```bash
sudo brr prog --stats
```

Show runtime deltas:

```bash
sudo brr activity --duration 2 --limit 10
sudo brr activity -x --duration 2
sudo brr activity -c --duration 2
```

Inspect a program by ID:

```bash
sudo brr dump 48
sudo brr top --program-id 48
```

Profile BPF JIT CPU samples:

```bash
sudo brr profile --duration 5 --event auto
```

List perf events that `brr` can open on the current host:

```bash
sudo brr perf-events
```

If `brr` is installed in a user-local path and you run it with `sudo`, preserve
your `PATH`:

```bash
sudo env PATH="$PATH" brr
```

## Build Release Artifacts

Release artifacts are built locally from the current checkout. The standalone
binary is native to the build machine, so build on each target architecture.

```bash
uv sync --group dev --group package
uv run --group package python scripts/build_release.py --all
```

Artifacts are written to `dist/release/`:

- `brr-0.4.1-linux-<arch>`
- `brr_0.4.1-1_<deb-arch>.deb`
- `brr-0.4.1-1.<rpm-arch>.rpm`
- `SHA256SUMS`

## Notes

- Default bpffs path: `/sys/fs/bpf`
- Optional `bpftool`: enriches mixed inspect output when available
- `perf` command-line tool: not used by `brr`
- Runtime stats are enabled temporarily with `BPF_ENABLE_STATS`; `brr` does not
  write to `/proc/sys/kernel/bpf_stats_enabled`
