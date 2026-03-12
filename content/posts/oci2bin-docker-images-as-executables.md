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

See `sysfatal` [blog post](https://sysfatal.github.io/polyglottar-en.html) which describes `ELF+TAR polygot`.

_ELF_ magic lives at byte 0 (`7f 45 4c 46`), while tar's ustar magic sits at byte 257. These don't overlap, so one file can satisfy both formats at once.

The file layout looks like this:


    [0-63]       ELF64 header (fits within the tar filename field)
    [64-511]     Remaining tar header (ustar magic at byte 257)
    [512-4095]   NUL padding (page-aligns the loader for mmap)
    [4096-~75K]  Loader binary (statically linked C)
    [~75K-end]   OCI image tar (manifest.json, config, layer tarballs)


The `build_polyglot.py` script parses the loader's _ELF_ to extract entry points and program headers, builds a synthetic _ELF64_ header, creates the tar header structure around it, and appends the OCI image data. Marker offsets (`OCI_DATA_OFFSET`, `OCI_DATA_SIZE`) are patched into the binary so the loader knows where to find the embedded image.

## The Loader

When you execute the binary, the loader (statically linked in C, no dependencies) does the following:

1. Reads `/proc/self/exe` to find itself
2. Seeks to the embedded OCI tar and extracts it to a temp directory
3. Extracts all image layers into a `rootfs/`
4. Patches the rootfs for single-UID namespace operation (rewrites `/etc/passwd`, disables apt sandbox, copies host DNS)
5. Sets up Linux namespaces: `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWUTS`, and optionally `CLONE_NEWNET`
6. Maps host UID to container UID 0 via user namespace
7. Bind-mounts volumes, secrets, devices, tmpfs
8. `chroot`s into the rootfs and execs the entrypoint

All rootless. The only dependency on the target system is `tar`.

## Security

The loader applies a `seccomp-BPF` filter by default, blocking syscalls like `kexec_load`, `reboot`, `ptrace`, `bpf`, and `init_module`. It sets `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation. Tar extraction runs with `--no-same-permissions --no-same-owner` so setuid bits don't survive. The temp directory is created with `mkdtemp` (mode `0700`).

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

