---
title: "oci2bin: Docker Images as Single Executables"
date: 2026-03-11T12:00:00+02:00
tags: ["docker", "containers", "linux", "oci", "namespaces"]
ShowToc: true
TocOpen: true
---

# Overview

[oci2bin](https://github.com/latedeployment/oci2bin) converts any Docker (OCI) container image into a single, self-contained executable. It doesn't require any Docker daemon, no container runtime, and no installation on the target machine as the binary is static. Just copy the file over and run it.

The output is a **polyglot file** which is simultaneously a valid _ELF64_ executable and a valid _POSIX tar_ archive which itself is an _OCI image_.

# How It Works

## The Polyglot Format

The output is a polyglot file — valid as both an _ELF64_ executable and a _POSIX tar_ archive simultaneously. This works because the two formats' magic bytes don't collide: _ELF_ magic (`7f 45 4c 46`) lives at byte 0, while tar's ustar magic sits at byte 257. The 64-byte _ELF_ header fits entirely within the tar filename field (bytes 0–99), and the remaining tar header fields fill bytes 64–511 without touching the _ELF_ magic. See `sysfatal`'s [blog post](https://sysfatal.github.io/polyglottar-en.html) for more on the `ELF+TAR` polyglot technique.

The file layout:

    [0-63]       ELF64 header (embedded in tar's filename field)
    [64-511]     Remaining tar header (ustar magic at byte 257)
    [512-4095]   NUL padding (page-aligns the loader for mmap)
    [4096-~75K]  Loader binary (statically linked C)
    [~75K-end]   OCI image tar (manifest.json, config, layer tarballs)
    [EOF]        Metadata block (image name, digest, timestamp)

The `build_polyglot.py` script parses the loader's _ELF_ to extract entry points and program headers, then builds a synthetic _ELF64_ header and wraps it in a tar header structure. The loader's program header offsets are shifted by `PAGE_SIZE` (4096 bytes) to account for the tar header prefix, while keeping virtual addresses unchanged — maintaining the `p_offset % PAGE_SIZE == p_vaddr % PAGE_SIZE` invariant required for `mmap`.

The loader binary contains placeholder marker values that are patched at build time:

- `OCI_DATA_OFFSET` — patched with the byte offset where the OCI tar begins
- `OCI_DATA_SIZE` — patched with the OCI tar's size in bytes
- `OCI_PATCHED` — set to confirm patching succeeded

This is how the loader knows where to find the embedded image inside itself.

## The Loader

When you execute the binary, the loader (~2800 lines of statically linked C, no dependencies) runs the following sequence:

1. Reads `/proc/self/exe` to find its own path
2. Verifies the `OCI_PATCHED` marker, then seeks to `OCI_DATA_OFFSET` and extracts the embedded OCI tar to a temp directory (`mkdtemp`, mode `0700`)
3. Parses `manifest.json` from the extracted OCI tar to get the layer list and config
4. Extracts each image layer in order into a `rootfs/`, validating every path against traversal attacks (rejects `..` components and absolute paths)
5. Patches the rootfs for single-UID namespace operation:
   - Rewrites `/etc/passwd` and `/etc/group` — maps all UIDs/GIDs to 0 (except `nobody` at 65534)
   - Writes `/etc/apt/apt.conf.d/99oci2bin` to disable apt's sandbox (which would fail under UID remapping)
   - Replaces `/etc/resolv.conf` with the host's actual resolver config (the chroot can't follow symlinks outside the rootfs)
6. Enters the user namespace (`CLONE_NEWUSER`) and maps container UID/GID 0 to the invoking user's real UID/GID — no real root privileges are gained
7. Enters mount, PID, and UTS namespaces (`CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS`), and optionally the network namespace (`CLONE_NEWNET` with `--net none`)
8. Forks — the child becomes PID 1 in the new PID namespace, the parent waits and cleans up the temp directory on exit
9. Child sets up bind mounts for volumes, secrets, SSH agent forwarding, and optionally an overlayfs for `--read-only` mode
10. `chroot`s into the rootfs, mounts `/proc`, `/tmp`, `/dev` (with device nodes: null, zero, random, urandom, tty), applies seccomp filter and capability restrictions
11. `exec`s the entrypoint

All rootless. No daemon, no suid helper. The only dependency on the target system is `tar`.

## Security

**Seccomp-BPF filtering.** The loader installs a BPF filter (with architecture validation) that blocks 16 dangerous syscalls by default: `kexec_load`, `kexec_file_load`, `reboot`, `syslog`, `perf_event_open`, `bpf`, `add_key`, `request_key`, `keyctl`, `userfaultfd`, `pivot_root`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `init_module`, and `finit_module`. The filter is applied with `SECCOMP_FILTER_FLAG_TSYNC` to cover all threads, falling back to `prctl(PR_SET_SECCOMP)` if unavailable. Can be disabled with `--no-seccomp`.

**Privilege escalation prevention.** `PR_SET_NO_NEW_PRIVS` is set before exec, preventing privilege gains through setuid binaries or file capabilities. The user namespace maps only a single UID/GID — container root is just the invoking user on the host.

**Capability management.** Linux capabilities can be dropped and selectively re-added (`--cap-drop all --cap-add NET_BIND_SERVICE`). The loader manages the permitted set, inheritable set, ambient set, and the bounding set — dropping from the bounding set is permanent for the process lifetime.

**Tar extraction safety.** Layers are extracted with `--no-same-permissions --no-same-owner`, stripping setuid/setgid bits and ignoring the original file ownership. Every layer path is validated to reject `..` components and absolute paths before extraction.

**Symlink attack prevention.** Secret files, SSH agent sockets, and device mounts are created with `O_CREAT | O_EXCL`, which fails atomically if the path already exists — preventing a malicious image layer from planting symlinks that redirect mounts outside the rootfs.

**Temp directory isolation.** All extraction happens in a `mkdtemp`-created directory (mode `0700`), cleaned up by the parent process on exit.

# Installation

## Build Dependencies

- `gcc` -- C compiler
- `glibc-static` -- static C library headers (Debian: `libc6-dev`)
- `python3` -- build scripts (stdlib only, no pip packages)
- `docker` -- to pull/save images (`skopeo` support is next)

## Install

{{< highlight bash >}}
git clone https://github.com/latedeployment/oci2bin
cd oci2bin
make
make install PREFIX=/usr/local
{{< / highlight >}}

The loader is compiled automatically on first invocation if not already built.

# Usage

## Basic

{{< highlight bash >}}
# Convert an image to an executable
oci2bin alpine:latest

# This produces ./alpine_latest
./alpine_latest

# Override the entrypoint
./alpine_latest /bin/sh
{{< / highlight >}}

That's it. `alpine_latest` is a standalone binary you can `scp` to any Linux box and run.

## Build-Time Options

{{< highlight bash >}}
# Cross-compile for aarch64
oci2bin --arch aarch64 alpine:latest

# Strip docs, man pages, locales, apt caches from the image
oci2bin --strip myapp:latest

# Inject files at build time
oci2bin --add-file config.yml:/etc/app/config.yml myapp:latest

# Inject an entire directory
oci2bin --add-dir certs:/etc/ssl/certs myapp:latest

# Merge additional layers on top
oci2bin --layer debugtools:latest myapp:latest

# Cache builds (keyed by image digest)
oci2bin --cache --strip myapp:latest
{{< / highlight >}}

## Runtime Flags

The generated binary accepts Docker-like flags:

{{< highlight bash >}}
# Environment variables
./myapp -e DB_HOST=localhost -e DB_PORT=5432
./myapp --env-file .env

# Volumes
./myapp -v /host/data:/data
./myapp -v $(pwd)/logs:/var/log/app

# Secrets (read-only mounts)
./myapp --secret api_key.txt:/run/secrets/api_key

# Forward SSH agent
./myapp --ssh-agent

# Networking
./myapp --net host       # default, shares host network
./myapp --net none       # isolated, no network

# Read-only rootfs (overlayfs copy-on-write)
./myapp --read-only

# Run as specific user
./myapp --user 1000:1000

# Resource limits
./myapp --ulimit nofile=1024 --ulimit nproc=512

# Capabilities
./myapp --cap-drop all --cap-add NET_BIND_SERVICE

# Device access
./myapp --device /dev/sda:/dev/sda

# Detach (fork to background)
./myapp -d

# Init process (reaps zombies, forwards signals)
./myapp --init

# Separate flags from args
./myapp -- -v   # the -v here is passed to the entrypoint, not oci2bin
{{< / highlight >}}

## Subcommands

{{< highlight bash >}}
# Inspect embedded metadata
oci2bin inspect ./myapp

# List cached binaries
oci2bin list
oci2bin list --json

# Prune outdated cache entries
oci2bin prune
oci2bin prune --dry-run

# Diff two binaries' filesystems
oci2bin diff ./myapp_v1 ./myapp_v2
{{< / highlight >}}

# Use Cases

* Ship a Service Without Docker
* Air-Gapped Environments
* Reproducible Dev Environments
* Lock Down a Container

# The Polymorphic Binary Trick

The same file works in three ways:

{{< highlight bash >}}
# As an executable
./myapp

# As a tar archive
tar tf ./myapp

# As a Docker image
docker load < ./myapp
docker run myapp:latest
{{< / highlight >}}

So if you ever do need Docker again, the binary is a valid image you can `docker load` right back.

