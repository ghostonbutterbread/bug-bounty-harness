"""Internal, offline-only Chrome user-data snapshot building block.

Not an authority source or a CLI. The manager must hold an exclusive source fence
and supply a fresh proof reader which independently checks lease, unit, root and
CDP termination. This module cannot certify that Chrome is stopped by itself.
"""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import uuid
from typing import Callable


class SnapshotRefused(RuntimeError):
    """No snapshot remains after refusal; message contains no profile content."""


class SnapshotCleanupIncomplete(SnapshotRefused):
    """Rollback could not be verified; private snapshot material may remain."""

    def __init__(self, original_failure: BaseException):
        super().__init__("profile snapshot cleanup incomplete; private material may remain")
        self.original_failure = original_failure


@dataclass(frozen=True)
class TerminalProof:
    program: str
    auth_domain: str
    account: str
    generation: str
    lease_id: str
    profile_path: str
    source_device: int
    source_inode: int
    unit: str
    root_identity: str
    cdp_identity: str
    unit_terminal: bool
    root_terminal: bool
    cdp_terminal: bool
    singleton_lock_absent: bool


# Runtime lock/socket artifacts and proxy CA material are never portable. NSS
# databases can include an imported task CA; omit them entirely, not just the
# PEM file. This can make client-certificate authentication unavailable.
_EXCLUDE = {"SingletonLock", "SingletonSocket", "SingletonCookie", "DevToolsActivePort",
            "cert9.db", "key4.db", "pkcs11.txt"}
_EXCLUDE_LOWER = {name.lower() for name in _EXCLUDE}


def _excluded(name: str) -> bool:
    lower = name.lower()
    return (lower in _EXCLUDE_LOWER or lower.endswith((".sock", ".socket"))
            or "mitmproxy" in lower or "task-proxy" in lower
            or lower.endswith((".pem", ".crt", ".key")))


def _sig(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def _open_root(root: Path, identity: tuple[int, int]) -> int:
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != identity:
        os.close(fd)
        raise SnapshotRefused("source physical identity changed")
    return fd

def _scan(root: Path, identity: tuple[int, int]) -> dict[str, tuple[int, ...]]:
    entries = {}
    def visit(fd: int, rel: Path) -> None:
        for name in sorted(os.listdir(fd)):
            if _excluded(name):
                continue
            relative = rel / name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)) or (stat.S_ISREG(st.st_mode) and st.st_nlink != 1):
                raise SnapshotRefused("unsupported profile entry (link, socket, or hardlink)")
            entries[str(relative)] = _sig(st)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if _sig(os.fstat(child)) != _sig(st):
                        raise SnapshotRefused("directory changed during scan")
                    visit(child, relative)
                finally:
                    os.close(child)
    fd = _open_root(root, identity)
    try:
        visit(fd, Path())
    finally:
        os.close(fd)
    return entries


def _open_parent(root: Path, relative: Path, entries: dict[str, tuple[int, ...]],
                 identity: tuple[int, int]) -> int:
    fd = _open_root(root, identity)
    try:
        for index, part in enumerate(relative.parts[:-1]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            prefix = relative.parts[:index + 1]
            # Compare the opened directory, not a subsequently replaced path.
            if _sig(os.fstat(fd)) != entries[str(Path(*prefix))]:
                raise SnapshotRefused("source directory changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_owned_tree(path: Path) -> None:
    """Remove our private tree, restoring traversal permission on copied dirs only."""
    def walk_error(error: OSError) -> None:
        raise error

    for root, dirs, _ in os.walk(path, topdown=True, followlinks=False, onerror=walk_error):
        os.chmod(root, 0o700, follow_symlinks=False)
        # os.walk does not descend through links; rmtree must reject surprises.
        for name in dirs:
            child = Path(root) / name
            if child.is_symlink():
                raise OSError("linked destination directory during cleanup")
    shutil.rmtree(path)
    if os.path.lexists(path):
        raise OSError("destination removal could not be verified")
    _fsync_dir(path.parent)


def _check(proof_reader: Callable[[], TerminalProof], expected: TerminalProof, source: Path) -> None:
    if proof_reader() != expected:
        raise SnapshotRefused("manager terminal proof changed")
    st = source.lstat()
    if not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != (expected.source_device, expected.source_inode):
        raise SnapshotRefused("source physical identity changed")
    if os.path.lexists(source / "SingletonLock"):
        raise SnapshotRefused("profile lock appeared")


def snapshot_stopped_profile(source: Path, private_parent: Path,
                             proof_reader: Callable[[], TerminalProof]) -> Path:
    """Publish a private snapshot; callable must revalidate manager state under its fence.

    Only a manager holding an exclusive no-restart fence can use this safely.
    No authentication or complete Chrome compatibility is asserted. Returned
    path is private capability material and must not enter public receipts.
    """
    staging = None
    final = None
    try:
        proof = proof_reader()
        if (not isinstance(proof, TerminalProof) or not all((proof.program, proof.auth_domain,
            proof.account, proof.generation, proof.lease_id, proof.unit, proof.root_identity,
            proof.cdp_identity)) or not all((proof.unit_terminal, proof.root_terminal,
            proof.cdp_terminal, proof.singleton_lock_absent))):
            raise SnapshotRefused("complete manager terminal proof required")
        source = Path(source).absolute()
        private_parent = Path(private_parent).absolute()
        if source.is_symlink() or private_parent.is_symlink():
            raise SnapshotRefused("linked root refused")
        if str(source) != proof.profile_path:
            raise SnapshotRefused("source path differs from proof")
        pst = private_parent.lstat()
        sst = source.lstat()
        if (not stat.S_ISDIR(pst.st_mode) or pst.st_mode & 0o077
                or pst.st_dev != sst.st_dev or source == private_parent
                or source in private_parent.parents or private_parent in source.parents):
            raise SnapshotRefused("private same-filesystem independent parent required")
        _check(proof_reader, proof, source)
        identity = (proof.source_device, proof.source_inode)
        initial = _scan(source, identity)
        needed = sum(v[3] for v in initial.values() if stat.S_ISREG(v[2]))
        space = os.statvfs(private_parent)
        if space.f_bavail * space.f_frsize < needed * 2 + 1024 * 1024:
            raise SnapshotRefused("insufficient disk space")
        candidate = private_parent / (".snapshot-" + uuid.uuid4().hex)
        candidate.mkdir(mode=0o700)
        staging = candidate
        directories = [Path(".")]
        for relative, signature in initial.items():
            _check(proof_reader, proof, source)
            src = source / relative
            dst = staging / relative
            if stat.S_ISDIR(signature[2]):
                dst.mkdir(mode=0o700)
                directories.append(Path(relative))
                continue
            parent_fd = _open_parent(source, Path(relative), initial, identity)
            try:
                fd = os.open(Path(relative).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            try:
                if _sig(os.fstat(fd)) != signature:
                    raise SnapshotRefused("source file changed")
                with os.fdopen(fd, "rb", closefd=False) as inp, open(dst, "xb") as out:
                    while data := inp.read(1024 * 1024):
                        out.write(data)
                        _check(proof_reader, proof, source)
                    out.flush()
                    os.fchmod(out.fileno(), stat.S_IMODE(signature[2]))
                    os.fsync(out.fileno())
                if _sig(os.fstat(fd)) != signature or _sig(src.lstat()) != signature:
                    raise SnapshotRefused("source file changed during copy")
            finally:
                os.close(fd)
        if _scan(source, identity) != initial:
            raise SnapshotRefused("source tree changed during copy")
        _check(proof_reader, proof, source)
        manifest = {"schema": 1, "source": asdict(proof), "file_count": sum(
            stat.S_ISREG(v[2]) for v in initial.values()), "auth_verified": False}
        with open(staging / "snapshot-manifest.json", "x", encoding="utf-8") as out:
            json.dump(manifest, out, sort_keys=True)
            out.flush()
            os.fchmod(out.fileno(), 0o600)
            os.fsync(out.fileno())
        for relative in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            dest = staging / relative
            if relative != Path("."):
                os.chmod(dest, stat.S_IMODE(initial[str(relative)][2]))
            _fsync_dir(dest)
        _check(proof_reader, proof, source)
        candidate_final = private_parent / ("snapshot-" + uuid.uuid4().hex)
        _fsync_dir(private_parent)
        os.rename(staging, candidate_final)
        final, staging = candidate_final, None
        _fsync_dir(private_parent)
        return final
    except BaseException as failure:
        owned = final if final is not None else staging
        if owned is not None:
            try:
                _remove_owned_tree(owned)
            except BaseException as cleanup_failure:
                raise SnapshotCleanupIncomplete(failure) from cleanup_failure
        if isinstance(failure, (OSError, ValueError)):
            raise SnapshotRefused("profile snapshot I/O failure") from failure
        raise
