#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    echo "Usage: $0 NUM_PROCESSES SECONDS" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

num_processes=$1
duration=$2

if [[ ! $num_processes =~ ^[1-9][0-9]*$ ]]; then
    echo "NUM_PROCESSES must be a positive integer" >&2
    exit 2
fi

if [[ ! $duration =~ ^[1-9][0-9]*$ ]]; then
    echo "SECONDS must be a positive integer" >&2
    exit 2
fi

fio_bin=$(command -v fio || true)
biolatency_bin=$(command -v biolatency || true)

if [[ -z $fio_bin ]]; then
    echo "fio was not found in PATH" >&2
    exit 1
fi

if [[ -z $biolatency_bin ]]; then
    echo "biolatency was not found in PATH" >&2
    exit 1
fi

fio_file=${FIO_FILE:-/nvme/brr-validation.dat}
fio_size=${FIO_SIZE:-8G}
fio_log=${FIO_LOG:-fio.txt}
biolatency_log=${BIOLATENCY_LOG:-biolatency.txt}

fio_pid=""
biolatency_pid=""

stop_workload() {
    local pid

    pid=$fio_pid
    fio_pid=""
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi

    pid=$biolatency_pid
    biolatency_pid=""
    if [[ -n $pid ]] && sudo -n kill -0 "$pid" 2>/dev/null; then
        sudo -n kill -INT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

on_exit() {
    local status=$?
    trap - EXIT INT TERM
    stop_workload
    exit "$status"
}

trap on_exit EXIT INT TERM

if [[ ! -e $fio_file ]]; then
    echo "Preparing $fio_size validation file at $fio_file..."
    "$fio_bin" \
        --name=prepare \
        --filename="$fio_file" \
        --size="$fio_size" \
        --rw=write \
        --bs=1M \
        --ioengine=psync \
        --direct=1 \
        --end_fsync=1
fi

# Authenticate before starting sudo in the background, where it cannot safely prompt.
sudo -v

echo "Starting biolatency -TQDF 5; output: $biolatency_log"
sudo -n "$biolatency_bin" -TQDF 5 >"$biolatency_log" 2>&1 &
biolatency_pid=$!

# Give biolatency a moment to load and attach its BPF programs before fio begins.
sleep 1
if ! sudo -n kill -0 "$biolatency_pid" 2>/dev/null; then
    echo "biolatency exited before fio started; see $biolatency_log" >&2
    wait "$biolatency_pid" || true
    biolatency_pid=""
    exit 1
fi

echo "Starting $num_processes fio processes for $duration seconds; output: $fio_log"
"$fio_bin" \
    --name=read-load \
    --filename="$fio_file" \
    --size="$fio_size" \
    --rw=randread \
    --bs=4k \
    --ioengine=psync \
    --direct=1 \
    --iodepth=1 \
    --numjobs="$num_processes" \
    --thread=0 \
    --time_based \
    --runtime="$duration" \
    --norandommap \
    >"$fio_log" 2>&1 &
fio_pid=$!

fio_status=0
wait "$fio_pid" || fio_status=$?
fio_pid=""

stop_workload
trap - EXIT INT TERM

echo "Workload complete. fio: $fio_log; biolatency: $biolatency_log"
exit "$fio_status"
