# scx_kestrel

Kestrel's `sched_ext` scheduler. It is a fork of
[`scx_layered`](https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_layered)
that classifies the desktop's tasks into Kestrel resource classes, so the
scheduler knows the compositor from a background browser process.

This repo is `kestrel-distro/scx`, a fork of [`sched-ext/scx`](https://github.com/sched-ext/scx).
It carries the whole upstream tree so `scx_kestrel` builds against the same
shared BPF headers and `scx_utils` as the other schedulers; only
`scheds/rust/scx_kestrel` and a `Cargo.toml` member line are Kestrel-specific.

## The two classification paths

`scx_kestrel` adds one match kind, `KestrelHint`, to `scx_layered`'s model:

- **`KestrelHint`** reads the kernel's per-task hint with `scx_bpf_task_hint()`
  (added by the kernel-bridge patch in `kestrel-distro/kernel`). Userspace sets
  it through `sched_setattr(2)` with `SCHED_FLAG_KESTREL_HINT` via
  `libkestrel-hint`. No userspace task-storage map is involved, so the broker
  needs no `CAP_BPF`.
- **cgroup classes** remain as the fallback: `kestrel-broker` moves tasks into
  `kestrel.slice/kestrel-*.slice`, and `CgroupContains` matches them. This path
  works on a stock kernel, before the hint patch lands.

The baked config is `kestrel-layers.json`. Layer order is precedence: the
first match wins, so the hint layers sit ahead of the cgroup layers and the
catch-all open layer sits last. Hint values are Kestrel-defined:

| Hint | Class |
|---|---|
| 1 | desktop (Quickshell, compositor-adjacent) |
| 2 | term (Ghostty) |
| 3 | browser active |
| 4 | browser background |
| 5 | game |

## Building

Part of the upstream cargo workspace:

```
cargo build --release -p scx_kestrel
```

`scx_kestrel` needs the Kestrel kernel (or any kernel with the
`scx_bpf_task_hint` kfunc) for the hint path; on a kernel without it, drop the
`KestrelHint` layers and keep the cgroup layers.

## Running

```
sudo scx_kestrel f:kestrel-layers.json
```

Register it with the loader like any other scheduler once the binary is on
`PATH`: `scxctl start --sched scx_kestrel`. `kestrel scx` in the payload drives
the same loader, so no payload change is needed.

## Keeping up to date

`.github/workflows/sync-upstream.yml` merges `sched-ext/scx` into this fork
daily. The expected divergence is `scheds/rust/scx_kestrel`, the member line in
`Cargo.toml`, and this repository's workflows. The `sched_ext` BPF ABI is
explicitly unstable across kernels, so a merge that moves the kfunc or ops
tables is a signal to rebuild both `scx_kestrel` and `linux-kestrel` in the same
cycle.
