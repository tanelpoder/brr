# AGENTS.md

## Project overview

`brr` is a Linux-only Python 3.11+ CLI and Textual TUI for observing loaded
eBPF objects. It is intended to feel like `ps` and `top` for eBPF: it lists
programs, maps, links, and BTF objects; measures program activity; dumps and
annotates translated instructions; and profiles BPF JIT execution.

The program accesses the kernel directly with `bpf()` and `perf_event_open()`.
Do not introduce a dependency on the `perf` command. `bpftool` is optional and
is currently used only where its output is explicitly compared with or mixed
into brr's own inspection data.

Most live commands require Linux root privileges or equivalent capabilities.
Keep ordinary development and unit tests runnable without root by injecting or
mocking collectors, perf openers, sample data, and sleeper functions.

## Repository map

- `src/brr/cli.py`: argparse definitions, output selection, command dispatch,
  and expected-error handling. `brr`, `python -m brr`, and the packaged binary
  all lead here.
- `src/brr/models.py`: shared dataclasses passed between collection, analysis,
  and rendering layers.
- `src/brr/app.py` and `src/brr/collector/service.py`: object wiring and the
  high-level snapshot, activity, dump, and profile workflows.
- `src/brr/collector/syscall.py`: Linux BPF syscall numbers, `ctypes` ABI
  structures, object enumeration, runtime-stat guards, and object metadata.
- `src/brr/collector/bpffs.py`: best-effort discovery of pinned objects below
  the configured bpffs mount (default `/sys/fs/bpf`).
- `src/brr/bpf_details.py`: BTF string parsing, instruction decoding,
  source-line mapping, and BPF JIT range resolution.
- `src/brr/profiler.py`: perf event discovery/opening, mmap ring parsing,
  kallsyms resolution, and attribution of samples to BPF programs and source.
- `src/brr/reporter.py`, `src/brr/inspection.py`, and
  `src/brr/source_context.py`: report aggregation, source/mixed inspection
  rows, optional `bpftool` enrichment, and `--devmode` source-tree enrichment.
- `src/brr/top.py`: deterministic `top --textmode` output and the interactive
  Textual application. Keep non-UI helpers independently testable.
- `src/brr/render/`: human-readable text plus JSON and CSV serializers.
  `brr_text.py` contains the top/inspect-specific text reports.
- `src/brr/dump_compare.py`: compares brr's decoded dump and source metadata
  with `bpftool`; mismatches intentionally produce exit status 1.
- `scripts/build_release.py`: native PyInstaller, DEB, RPM, and checksum build.
- `scripts/build_rhel8_release.sh` and `Containerfile.rhel8`: native-architecture
  GLIBC 2.28 release build and package/runtime verification.
- `README.md`: user-facing install/usage overview. `EXAMPLE_OUTPUT.md` shows
  richer profiler reports, and `PACKAGING.md` is the release procedure.

## Development commands

Use `uv` and run commands from the repository root:

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run python -m pytest -q
uv run brr --help
```

The configured test location is `tests/`, with `correctness`, `live`, and
`stress` markers. Add focused tests there for behavior changes. Unit tests
should use synthetic kernel/perf records and fakes. Clearly mark tests that
require live eBPF state, special kernel support, workloads, or elevated
privileges.

For manual live checks, use a Linux host with suitable privileges, for example:

```bash
sudo env PATH="$PATH" uv run brr
sudo env PATH="$PATH" uv run brr activity --duration 1
sudo env PATH="$PATH" uv run brr top --textmode --delay 1
sudo env PATH="$PATH" uv run brr perf-events
```

For interactive TUI smoke tests, a detached `tmux` session plus
`tmux capture-pane -p` provides a clean snapshot of the rendered screen without
the raw ANSI redraw stream produced by a PTY. Fixing the window size is also
useful for checking narrow-terminal wrapping and clipping:

```bash
tmux new-session -d -s brr-smoke -x 80 -y 24 \
  'sudo env PATH="$PATH" uv run brr'
tmux capture-pane -p -t brr-smoke
tmux send-keys -t brr-smoke Enter
tmux capture-pane -p -t brr-smoke
tmux send-keys -t brr-smoke p
tmux capture-pane -p -t brr-smoke
tmux send-keys -t brr-smoke C-q
tmux kill-session -t brr-smoke 2>/dev/null || true
```

Send keys only after the relevant table or modal has loaded, and capture again
after asynchronous profiling or inspection work completes. This is a manual
live check, not a replacement for deterministic headless Textual tests.

Do not make a live/root check the only verification for logic that can be
covered with deterministic inputs.

## Code conventions and invariants

- Follow the Ruff configuration in `pyproject.toml`: Python 3.11, 100-character
  lines, import sorting, and the selected `E`, `F`, `I`, `B`, and `UP` rules.
- Continue using modern type hints and small, typed dataclasses. Shared external
  data belongs in `models.py`; view-specific report types may stay near their
  aggregation logic.
- Preserve layer boundaries. Kernel reads belong in collectors/profiler code,
  orchestration in the service, derived presentation data in reporter or
  inspection code, and formatting in renderers.
- Prefer dependency injection for syscall, perf, clock/sleep, filesystem, and
  subprocess boundaries. Existing `sleeper`, opener, collector, and resolver
  parameters are deliberate test seams.
- Treat kernel resources carefully: close file descriptors and mmap handles on
  every path, including exceptions. Runtime stats must remain scoped by
  `RuntimeStatsGuard`; do not toggle `/proc/sys/kernel/bpf_stats_enabled`.
- Changes to syscall constants or `ctypes.Structure` layouts are ABI-sensitive.
  Verify sizes, field order, supported architectures, and behavior on kernels
  that lack newer fields or commands. The current direct syscall support is for
  x86_64 and aarch64/arm64.
- Convert expected privilege and feature failures to the `BrrError` hierarchy
  so the CLI retains its documented messages and exit codes. Do not hide
  unexpected programming errors.
- Keep collection and output deterministic: sort object IDs and pinned paths,
  retain stable tie-breakers, and preserve the convention that a limit of `0`
  means unlimited.
- When a model or report changes, audit every consumer: plain text, JSON, CSV,
  top textmode, and the Textual TUI. Machine-readable field names and shapes are
  public automation interfaces; change them intentionally and document it.
- Global output flags are also added to relevant subparsers so users can place
  them before or after the command. Preserve that CLI behavior when adding an
  option.
- Source metadata may be incomplete, paths may refer to a different build tree,
  and programs may have no JIT or line information. Preserve graceful fallback
  values instead of assuming all metadata exists.

## Documentation and releases

Update `README.md` when commands, flags, requirements, or user-visible output
change. Update `EXAMPLE_OUTPUT.md` when the richer activity/profile presentation
changes, and update `PACKAGING.md` for release-process changes.

Release builds are native to the build host. Never relabel an x86_64
PyInstaller payload as aarch64, or the reverse. Build the published standalone,
RPM, and DEB artifacts on each target architecture with:

```bash
scripts/build_rhel8_release.sh
```

This container path enforces the GLIBC 2.28 ceiling and install-tests the
packages on old runtime images. For a simpler build that only targets the
current host's GLIBC, use:

```bash
uv sync --group dev --group package
uv run --group package python scripts/build_release.py --all
```

Artifacts go to ignored `build/` and `dist/release/` directories. Verify the
standalone binary and package payload architecture as described in
`PACKAGING.md`. For a version bump, update `pyproject.toml`, the source-checkout
fallback in `src/brr/cli.py`, user-facing version examples in `README.md`, and
`uv.lock` as applicable.
