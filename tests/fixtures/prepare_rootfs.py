#!/usr/bin/env python3
"""Build a disposable Debian image without sudo or host package installation.

Usage: python3 tests/fixtures/prepare_rootfs.py --output /tmp/games-smoke-rootfs
Downloads the official Debian bookworm-slim OCI image, extracts inside a fully
mapped user namespace, then installs real test dependencies ONLY in that chroot.
Requires unshare/newuidmap/newgidmap, subordinate IDs, mount, ip and HTTPS access.
The rootfs is disposable; do not point this tool at an existing operating system.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

MARKER = ".games-repair-disposable-rootfs"
REPO = Path(__file__).resolve().parents[2]
REGISTRY = "https://registry-1.docker.io/v2/library/debian"
NAMESPACE = ["unshare", "--user", "--map-auto", "--map-root-user", "--mount",
             "--pid", "--fork", "--kill-child"]


def command(*args, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def isolation_required():
    mapping = Path("/proc/self/uid_map").read_text().splitlines()
    if os.geteuid() != 0 or len(mapping) < 2:
        raise RuntimeError("A subordinate-ID user namespace is mandatory; refusing host root")
    first = mapping[0].split()
    if first[0] != "0" or first[1] == "0" or first[2] != "1":
        raise RuntimeError("Namespace must map your unprivileged host UID to disposable root")
    if not any(int(row.split()[2]) >= 65536 for row in mapping[1:]):
        raise RuntimeError("At least 65536 subordinate IDs are required for real sshd/accounts")


def checked_root(path: Path) -> Path:
    if path.is_symlink():
        raise RuntimeError("Rootfs must not be a symlink")
    root = path.resolve()
    if root == Path("/") or not (root / MARKER).is_file():
        raise RuntimeError("Rootfs lacks the disposable fixture marker")
    if (root / MARKER).read_text() != "debian-bookworm-smoke-only\n":
        raise RuntimeError("Unexpected rootfs fixture marker")
    return root


def mount_runtime(root: Path):
    command("mount", "--make-rprivate", "/")
    for name in ("proc", "dev", "run"):
        (root / name).mkdir(exist_ok=True)
    command("mount", "-t", "proc", "proc", root / "proc")
    command("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", root / "dev")
    for name in ("null", "zero", "random", "urandom", "tty"):
        target = root / "dev" / name
        target.touch()
        command("mount", "--bind", "/dev/" + name, target)
    (root / "dev/pts").mkdir()
    command("mount", "-t", "devpts", "-o", "newinstance,ptmxmode=0666,mode=0620", "devpts", root / "dev/pts")
    (root / "dev/ptmx").symlink_to("pts/ptmx")
    (root / "dev/fd").symlink_to("/proc/self/fd")
    command("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", root / "run")


def request_json(url: str, token: str | None = None):
    headers = {"Accept": ", ".join(("application/vnd.oci.image.index.v1+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.docker.distribution.manifest.v2+json"))}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as response:
        return json.load(response)


def extract_layer(archive: Path, root: Path):
    # Extraction runs unprivileged in the same disposable user namespace. Reject
    # traversal and symlink destinations rather than trusting image path strings.
    with tarfile.open(archive) as tar:
        for member in tar:
            relative = Path(member.name)
            if relative == Path("."):
                continue
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise RuntimeError("Unsafe OCI archive member")
            target = root / relative
            if relative.name.startswith(".wh."):
                raise RuntimeError("Unexpected whiteout in single-base Debian layer")
            if member.isdev() or member.isfifo():
                continue  # Real /dev is mounted separately; no host device access.
            if not target.parent.resolve().is_relative_to(root):
                raise RuntimeError("OCI member escapes rootfs via symlink")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                target.unlink()
            if member.isdir():
                target.mkdir(exist_ok=True)
            elif member.issym():
                # Absolute image symlinks are legitimate, but later archive
                # writes through them are rejected by the parent check above.
                target.symlink_to(member.linkname)
            elif member.islnk():
                source = root / member.linkname
                if Path(member.linkname).is_absolute() or not source.resolve().is_relative_to(root):
                    raise RuntimeError("OCI hardlink escapes disposable rootfs")
                os.link(source, target, follow_symlinks=False)
            elif member.isfile():
                source = tar.extractfile(member)
                if source is None:
                    raise RuntimeError("Missing regular-file archive data")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with source, os.fdopen(descriptor, "wb") as destination:
                    shutil.copyfileobj(source, destination)
            else:
                raise RuntimeError("Unsupported OCI archive member type")
            os.chown(target, member.uid, member.gid, follow_symlinks=False)
            if not member.issym():
                target.chmod(member.mode)


def build(root: Path):
    isolation_required()
    if root.exists():
        raise RuntimeError("--output must not exist; refusing to alter an existing tree")
    root.mkdir(mode=0o700, parents=True)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
    if architecture is None:
        raise RuntimeError("Only amd64/arm64 fixture images are supported")
    token = request_json("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull")["token"]
    index = request_json(REGISTRY + "/manifests/bookworm-slim", token)
    if "manifests" in index:
        item = next(item for item in index["manifests"]
                    if item.get("platform", {}).get("architecture") == architecture
                    and item.get("platform", {}).get("os") == "linux")
        manifest = request_json(REGISTRY + "/manifests/" + item["digest"], token)
    else:
        manifest = index
    for layer in manifest["layers"]:
        digest = layer["digest"]
        if not digest.startswith("sha256:"):
            raise RuntimeError("Unexpected OCI digest algorithm")
        with tempfile.TemporaryDirectory(prefix="games-smoke-layer-") as temporary:
            blob = Path(temporary) / "layer.tar.gz"
            request = urllib.request.Request(REGISTRY + "/blobs/" + digest,
                                             headers={"Authorization": "Bearer " + token})
            calculated = hashlib.sha256()
            with urllib.request.urlopen(request, timeout=120) as source, blob.open("wb") as destination:
                while block := source.read(1024 * 1024):
                    calculated.update(block)
                    destination.write(block)
            if calculated.hexdigest() != digest.split(":", 1)[1]:
                raise RuntimeError("OCI image layer checksum mismatch")
            extract_layer(blob, root)
    (root / MARKER).write_text("debian-bookworm-smoke-only\n")
    shutil.copyfile("/etc/resolv.conf", root / "etc/resolv.conf")
    policy = root / "usr/sbin/policy-rc.d"
    policy.write_text("#!/bin/sh\nexit 101\n")
    policy.chmod(0o755)
    mount_runtime(root)
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}
    command("chroot", root, "/usr/bin/apt-get", "update", env=env)
    command("chroot", root, "/usr/bin/apt-get", "install", "-y", "--no-install-recommends",
            "python3", "openssh-server", "openssh-client", "sudo", "passwd", "procps",
            "util-linux", "systemd", "iproute2", env=env)
    command("chroot", root, "/usr/bin/apt-get", "clean", env=env)
    print(f"Disposable rootfs prepared: {root}", flush=True)


def enter_smoke(root: Path, forwarded: list[str]):
    isolation_required()
    root = checked_root(root)
    command("ip", "link", "set", "lo", "up")
    mount_runtime(root)
    destination = root / "opt/repair"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(REPO, destination, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    smoke = root / "run/smoke"
    smoke.mkdir(mode=0o700)
    (smoke / "isolation.json").write_text(json.dumps({
        "uid_map": Path("/proc/self/uid_map").read_text(),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "network_namespace": os.readlink("/proc/self/ns/net"),
    }))
    # Paths beneath the chroot are never exposed to production via environment
    # hooks: production executes unchanged against the disposable operating system.
    os.chroot(root)
    os.chdir("/opt/repair")
    os.environ.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C.UTF-8")
    os.execv("/usr/bin/python3", ["python3", "/opt/repair/tests/smoke_repair.py", "--inside", *forwarded])


def launch_smoke(root: Path, forwarded: list[str]):
    if os.getuid() == 0:
        raise RuntimeError("Run this fixture as your ordinary user, never sudo")
    root = checked_root(root)
    command(*NAMESPACE, "--net", sys.executable, Path(__file__).resolve(),
            "--enter-smoke", "--output", root, "--", *forwarded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inside-build", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--enter-smoke", action="store_true", help=argparse.SUPPRESS)
    args, forwarded = parser.parse_known_args()
    root = args.output.absolute()
    if args.enter_smoke:
        enter_smoke(root, forwarded[1:] if forwarded[:1] == ["--"] else forwarded)
    elif args.inside_build:
        build(root)
    else:
        if os.getuid() == 0:
            parser.error("Run as an ordinary user, never sudo")
        command(*NAMESPACE, sys.executable, Path(__file__).resolve(), "--inside-build", "--output", root)


if __name__ == "__main__":
    main()
