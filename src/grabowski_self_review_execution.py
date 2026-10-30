"""Fail-closed verification of server-executed self-review phase receipts.

This verifier is intentionally NOT a review producer.  A caller's report, even
if internally hashed, is never sufficient evidence that a phase was executed.
Only a trusted server issuer may sign phase receipts after observing a frozen,
read-only job and its task lifecycle/output evidence.

The signing principal is controlled by an operating-system trust root, not by
the PR under review.  Missing deployment of that trust root is a hard BLOCK.
"""
from __future__ import annotations

import hashlib
import ctypes
import fcntl
import json
import os
import pwd
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable

KIND = "grabowski_server_self_review_pass"
PRODUCER = "grabowski-self-review-runner"
PRINCIPAL = "grabowski-review-gate@heimgewebe"
NAMESPACE = "self-review-phase@grabowski.heimgewebe"
REQUIRED_AXES = (
    "contracts_correctness",
    "regression_compatibility",
    "tests_negative_cases",
    "security_authority_concurrency",
    "adversarial_countercheck",
)
RECEIPT_ROOT = Path.home() / ".local/state/grabowski/self-review-executions"
CAPTURE_ROOT = Path.home() / ".local/state/grabowski/task-output"
SIGNING_KEY = Path.home() / ".config/grabowski/self-review-phase-ed25519"
OUTCOME_ROOT = Path(os.environ.get("GRABOWSKI_TASK_DB", str(Path.home() / ".local/state/grabowski/tasks.sqlite3"))).expanduser().with_suffix(".outcomes")
# Nix store contains the already-reviewed, root-owned public signer allowlist.
# Never use a trust anchor from the candidate PR checkout.
_MODULE_PATH = Path(__file__).resolve()
_NIX_PREFIX = _MODULE_PATH.parents[3] if len(_MODULE_PATH.parents) > 3 else Path("/")
TRUSTED_SIGNERS = (
    _NIX_PREFIX / "share/grabowski/config/self-review-allowed-signers"
    if _NIX_PREFIX.is_relative_to(Path("/nix/store"))
    else Path("/nonexistent-grabowski-self-review-trust-root")
)
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"[a-f0-9]{32}\Z")
REF = re.compile(r"(?P<path>[A-Za-z0-9_.@+/-]+)(?::(?P<source_revision>[a-f0-9]{40}))?:L(?P<start>[1-9][0-9]{0,6})(?:-L(?P<end>[1-9][0-9]{0,6}))?\Z")
MAX_RECEIPT = 16384
MAX_RECORD_SIGNATURE = 16384
SIGNED_RECORD_ENVELOPE_KIND = "grabowski_signed_record_envelope_v1"
# Five substantial, independently signed axes plus a frozen Writer/Test origin
# can exceed the ordinary single-record limit without adding untrusted data.
MAX_CANDIDATE_FINALIZED_RECEIPT = 32768
MAX_OUTPUT = 1024 * 1024
MAX_SOURCE_BLOB = 2 * 1024 * 1024
MAX_REFERENCES = 64
PHASE_OBSERVATION_PREFIX = b"grabowski-phase-source-inspection-v1:"
FIRST_PARTY_REVIEW_ROOT = (
    Path.home() / ".local/state/grabowski/first-party-self-reviews"
)
FIRST_PARTY_SESSION_TTL_SECONDS = 24 * 60 * 60
FIRST_PARTY_MAX_DIFF_BYTES = 1024 * 1024
FIRST_PARTY_MAX_READ_BYTES = 256 * 1024
FIRST_PARTY_MAX_READ_LINES = 1000
FIRST_PARTY_SESSION_KIND = "grabowski_first_party_semantic_review_session_v1"
FIRST_PARTY_READ_KIND = "grabowski_first_party_semantic_source_read_v1"
FIRST_PARTY_AXIS_KIND = "grabowski_first_party_semantic_axis_review_v1"
FIRST_PARTY_ISSUER_KIND = "grabowski_authenticated_mcp_controller_v1"
FIRST_PARTY_AUDIT_ORIGIN = "first_party_authenticated_controller_v1"
FIRST_PARTY_TOOL_START = "grabowski_self_review_session_start"
FIRST_PARTY_TOOL_READ = "grabowski_self_review_source_read"
FIRST_PARTY_TOOL_SUBMIT = "grabowski_self_review_axis_submit"
FIRST_PARTY_CONNECTOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
FIRST_PARTY_READ_ID_RE = re.compile(r"[a-f0-9]{32}\Z")


class ReviewExecutionRejected(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _private_dir(path: Path) -> int:
    # No attacker-controlled symlink or permission-widened parent is admitted.
    before = path.lstat()
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise ReviewExecutionRejected("private execution directory authority invalid")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    current = os.fstat(fd)
    if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
        os.close(fd)
        raise ReviewExecutionRejected("private execution directory identity changed")
    return fd


def _private_read(fd: int, name: str, *, limit: int, allow_empty: bool = False) -> bytes:
    if "/" in name or name in {".", ".."} or len(name) > 100:
        raise ReviewExecutionRejected("private execution path invalid")
    item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        st = os.fstat(item)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_nlink != 1
            or stat.S_IMODE(st.st_mode) & 0o077
            or (st.st_size == 0 and not allow_empty) or st.st_size > limit
        ):
            raise ReviewExecutionRejected("private execution record identity invalid")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(item, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != st.st_size or len(data) > limit:
            raise ReviewExecutionRejected("private execution record changed during read")
        end = os.fstat(item)
        if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (
            end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns,
        ):
            raise ReviewExecutionRejected("private execution record drifted")
        return bytes(data)
    finally:
        os.close(item)


def _json_record(data: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(data)
        if not isinstance(decoded, dict) or _canonical(decoded) != data:
            raise ReviewExecutionRejected("execution record is not canonical JSON")
        return decoded
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ReviewExecutionRejected("execution record JSON invalid") from exc


def _allowed_signers(path: Path, *, root_owned: bool) -> Path:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size < 1:
        raise ReviewExecutionRejected("trusted signer allowlist unavailable")
    if root_owned and (st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022):
        raise ReviewExecutionRejected("trusted signer allowlist not root-protected")
    if not root_owned and stat.S_IMODE(st.st_mode) & 0o022:
        raise ReviewExecutionRejected("trusted signer allowlist writable by others")
    return path


def _trusted_root_owner(uid: int) -> bool:
    """Recognize host-root files mapped to overflow UID in a nested userns.

    Ordinary host callers must see uid=0. In a bubblewrap user namespace the
    outer root can be unmapped and appears as 65534; only accept that owner
    if /proc/self/uid_map proves uid 0 is unmapped and our UID is mapped.
    """
    if uid == 0:
        return True
    if uid != 65534:
        return False
    try:
        rows = [
            tuple(int(value) for value in line.split())
            for line in Path("/proc/self/uid_map").read_text(encoding="ascii").splitlines()
        ]
    except (OSError, ValueError, UnicodeError):
        return False
    if not rows or any(len(row) != 3 or row[2] <= 0 for row in rows):
        return False
    return (
        not any(inside <= 0 < inside + count for inside, _, count in rows)
        and any(inside <= os.getuid() < inside + count for inside, _, count in rows)
    )


def _trusted_ssh_keygen() -> str:
    """Never let user-controlled PATH choose the signature verification binary.

    NixOS and conventional Linux runners expose OpenSSH through known,
    root-managed locations. A missing or replaced binary rejects the review;
    the caller cannot supply a custom verifier.
    """
    for candidate in (
        Path("/run/current-system/sw/bin/ssh-keygen"),
        Path("/usr/bin/ssh-keygen"),
    ):
        try:
            original = candidate.lstat()
        except FileNotFoundError:
            continue
        try:
            real = candidate.resolve(strict=True)
            final = real.stat()
            parent = candidate.parent.stat()
        except OSError as exc:
            raise ReviewExecutionRejected("trusted OpenSSH path unavailable") from exc
        if (
            not _trusted_root_owner(original.st_uid)
            or not (stat.S_ISREG(original.st_mode) or stat.S_ISLNK(original.st_mode))
            or not _trusted_root_owner(parent.st_uid)
            or stat.S_IMODE(parent.st_mode) & 0o022
            or not stat.S_ISREG(final.st_mode)
            or not _trusted_root_owner(final.st_uid)
            or stat.S_IMODE(final.st_mode) & 0o022
            or not final.st_mode & stat.S_IXUSR
            or not (
                real.is_relative_to(Path("/nix/store"))
                or real == Path("/usr/bin/ssh-keygen")
            )
        ):
            raise ReviewExecutionRejected("trusted OpenSSH binary authority invalid")
        return str(real)
    raise ReviewExecutionRejected("trusted OpenSSH signature verifier missing")


def _check_signature(material: bytes, signature: bytes, signers: Path) -> None:
    # Pass the already-validated pinned bytes through an inherited private FD:
    # ssh-keygen never reopens an attacker-changeable signature pathname.
    if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
        raise ReviewExecutionRejected("self-review signature format invalid")
    if not hasattr(os, "memfd_create"):
        raise ReviewExecutionRejected("immutable signature descriptor unavailable")
    fd = os.memfd_create("grabowski-selfreview-sig", flags=0)
    try:
        os.write(fd, signature)
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            result = subprocess.run(
                [
                    _trusted_ssh_keygen(), "-Y", "verify", "-f", str(signers),
                    "-I", PRINCIPAL, "-n", NAMESPACE,
                    "-s", f"/proc/self/fd/{fd}",
                ],
                input=material, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(fd,), timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReviewExecutionRejected("self-review signature verifier unavailable") from exc
        if result.returncode != 0:
            raise ReviewExecutionRejected("self-review signature not authentic")
    finally:
        os.close(fd)



# A method is defined by an immutable entrypoint/argv shape, not by
# a caller's prose description or a freely selected task id.
METHOD_TEST_SUITE = {
    "contracts_correctness": "test_review_evidence_schemas.py",
    "regression_compatibility": "test_pr_review_gate_external.py",
    "tests_negative_cases": "test_self_review_execution.py",
    "security_authority_concurrency": "test_self_review_producer.py",
    "adversarial_countercheck": "test_pr_review_gate_recovery_risk_paths.py",
    "additional_adversarial_probe": "test_release_admission.py",
}
def _sandbox_bwrap_flags(worktree: str) -> list[str]:
    """Minimal review mount namespace: PR tests cannot read operator secrets.

    Bind only immutable Nix executables, system identity, the managed Git object
    store and the exact candidate checkout. Never bind /, /home or /run/user.
    An empty environment prevents secret-bearing parent variables leaking too.
    """
    candidate = Path(worktree)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ReviewExecutionRejected("review sandbox checkout path invalid")
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    if not home.is_absolute() or home == Path("/") or home == Path("/tmp"):
        raise ReviewExecutionRejected("review sandbox account home invalid")
    repos = home / "repos"
    git_dir = repos / "grabowski" / ".git"
    return [
        "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-net",
        "--tmpfs", "/",
        "--dir", "/nix", "--ro-bind", "/nix/store", "/nix/store",
        "--dir", "/run", "--dir", "/run/current-system",
        "--ro-bind", "/run/current-system/sw", "/run/current-system/sw",
        "--dir", "/etc", "--ro-bind", "/etc/passwd", "/etc/passwd",
        "--ro-bind", "/etc/group", "/etc/group",
        "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
        "--dir", "/home", "--dir", str(home),
        "--dir", str(repos), "--dir", str(repos / "grabowski"),
        "--ro-bind", str(git_dir), str(git_dir),
        "--dir", str(repos / ".grabowski-worktrees"),
        "--ro-bind", worktree, worktree,
        "--clearenv", "--setenv", "HOME", "/tmp",
        "--setenv", "PATH", "/run/current-system/sw/bin",
        "--setenv", "LANG", "C.UTF-8",
        "--chdir", worktree,
    ]
_BWRAP_NIX = re.compile(r"/nix/store/[0-9a-z]{32}-bubblewrap-[^/]+/bin/bwrap\Z")
_PYTHON_NIX = re.compile(r"/nix/store/[0-9a-z]{32}-grabowski-operator-[^/]+/bin/python3\Z")


def trusted_phase_source(
    binding: dict[str, Any], axis: str, worktree: str,
) -> str:
    """Immutable inline worker: reject source drift, read full Git delta, run fixed method.

    The binding is embedded in the actual systemd argv; merely changing a
    signed audit field cannot reuse an earlier successful task for another PR,
    base, head, diff, release, or batch.
    """
    suite = METHOD_TEST_SUITE.get(axis)
    if suite is None or not isinstance(binding, dict):
        raise ReviewExecutionRejected("review method or source binding invalid")
    if (
        not isinstance(worktree, str) or not worktree.startswith("/")
        or ".." in Path(worktree).parts
    ):
        raise ReviewExecutionRejected("review checkout binding invalid")
    literal = json.dumps(_canonical(binding).decode("utf-8"))
    root = json.dumps(worktree)
    selected = json.dumps(suite)
    return (
        "import hashlib,json,os,subprocess,sys,selectors,signal,time,types\n"
        f"binding=json.loads({literal})\n"
        f"repo={root}\n"
        f"suite={selected}\n"
        "def bounded(argv,limit,timeout):\n"
        "    env=os.environ.copy();env['GIT_OPTIONAL_LOCKS']='0'\n"
        "    child=subprocess.Popen(argv,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,start_new_session=True)\n"
        "    chunks=[];size=0;deadline=time.monotonic()+timeout\n"
        "    selector=selectors.DefaultSelector()\n"
        "    try:\n"
        "        selector.register(child.stdout,selectors.EVENT_READ)\n"
        "        while True:\n"
        "            remaining=deadline-time.monotonic()\n"
        "            if remaining<=0 or not selector.select(remaining):\n"
        "                raise TimeoutError('review subprocess deadline')\n"
        "            chunk=os.read(child.stdout.fileno(),65536)\n"
        "            if not chunk:break\n"
        "            size+=len(chunk)\n"
        "            if size>limit:raise ValueError('review command output over budget')\n"
        "            chunks.append(chunk)\n"
        "        status=child.wait(timeout=max(0.1,deadline-time.monotonic()))\n"
        "        return types.SimpleNamespace(stdout=b''.join(chunks),stderr=b'',returncode=status)\n"
        "    except (TimeoutError,ValueError,subprocess.TimeoutExpired):\n"
        "        try:os.killpg(child.pid,signal.SIGKILL)\n"
        "        except ProcessLookupError:pass\n"
        "        child.wait()\n"
        "        sys.exit(98)\n"
        "    finally:\n"
        "        selector.close();child.stdout.close()\n"
        "def run(*args,limit=2097152):\n"
        "    return bounded(['git','--no-replace-objects','-C',repo,*args],limit,60)\n"
        "head=run('rev-parse','HEAD')\n"
        "if head.returncode or head.stdout.strip().decode()!=binding['head_sha']:"
        "sys.exit(81)\n"
        "clean=run('status','--porcelain','--untracked-files=normal')\n"
        "if clean.returncode or clean.stdout:sys.exit(82)\n"
        "base=run('cat-file','-t',binding['base_sha'])\n"
        "if base.returncode or base.stdout.strip()!=b'commit':sys.exit(83)\n"
        "delta=run('diff','--no-ext-diff','--no-textconv','--no-renames',"
        "'--ignore-submodules=none','--raw','--abbrev=40','-z',binding['base_sha'],"
        "binding['head_sha'],'--')\n"
        "if delta.returncode or len(delta.stdout)>1048576:sys.exit(84)\n"
        "sys.stdout.buffer.write(b'source_raw_diff_sha256:'+hashlib.sha256(delta.stdout).hexdigest().encode()+b'\\n')\n"
        "probe=bounded([sys.executable,'-B','-m','unittest','discover','-s','tests','-p',suite,'-q'],1048576,240)\n"
        "sys.stdout.buffer.write(probe.stdout)\n"
        "import ast,re\n"
        f"axis={json.dumps(axis)}\n"
        "if probe.returncode:sys.exit(probe.returncode)\n"
        "# Inspect precisely the raw bytes whose SHA-256 is bound to this task.\n"
        "# Re-running a different diff command could silently omit raw changed paths.\n"
        "fields=delta.stdout.split(b'\\x00')\n"
        "if len(fields)<3 or fields[-1]!=b'':sys.exit(85)\n"
        "fields=fields[:-1]\n"
        "if len(fields)%2:sys.exit(85)\n"
        "changed=[];seen_changed=set()\n"
        "for pos in range(0,len(fields),2):\n"
        "    header=fields[pos]\n"
        "    if not header.startswith(b':'):sys.exit(85)\n"
        "    parts=header[1:].split(b' ')\n"
        "    if len(parts)!=5:sys.exit(85)\n"
        "    old_mode,new_mode,old_sha,new_sha,raw_status=parts\n"
        "    if not all(re.fullmatch(rb'[0-9a-f]{40}',oid) for oid in (old_sha,new_sha)):sys.exit(85)\n"
        "    try:status=raw_status.decode('ascii');path=fields[pos+1].decode('utf-8')\n"
        "    except UnicodeError:sys.exit(85)\n"
        "    if status not in ('A','D','M','T') or not re.fullmatch(r'[A-Za-z0-9_.@+/-]{1,512}',path) or '..' in path.split('/') or path in seen_changed:sys.exit(87)\n"
        "    if (status=='A' and old_mode!=b'000000') or (status=='D' and new_mode!=b'000000') or (status in ('M','T') and (old_mode==b'000000' or new_mode==b'000000')):sys.exit(87)\n"
        "    changed.append((status,path));seen_changed.add(path)\n"
        "if not changed or len(changed)>256:sys.exit(86)\n"
        "def blob_at(revision,path):\n"
        "    tree=run('ls-tree','-z',revision,'--',path,limit=4096)\n"
        "    if tree.returncode or tree.stdout.count(b'\\x00')!=1 or not tree.stdout.endswith(b'\\x00'):sys.exit(94)\n"
        "    try:\n"
        "        metadata,name=tree.stdout[:-1].split(b'\\t',1)\n"
        "        mode,kind,sha=metadata.split()\n"
        "        if name.decode('utf-8')!=path or mode not in (b'100644',b'100755') or kind!=b'blob' or len(sha)!=40:sys.exit(95)\n"
        "    except (ValueError,UnicodeError):sys.exit(95)\n"
        "    blob=run('show',revision+':'+path,limit=2097152)\n"
        "    if blob.returncode or b'\\x00' in blob.stdout:sys.exit(92)\n"
        "    try:return blob.stdout.decode('utf-8')\n"
        "    except UnicodeError:sys.exit(93)\n"
        "paths=[];refs=[];ast_stmts=0;defined_symbols=0;json_docs=0\n"
        "for status,path in changed:\n"
        "    sides=([binding['head_sha']] if status=='A' else [binding['base_sha']] if status=='D' else [binding['base_sha'],binding['head_sha']])\n"
        "    for revision in sides:\n"
        "        content=blob_at(revision,path)\n"
        "    if path.endswith('.py'):\n"
        "        try:tree=ast.parse(content,filename=path)\n"
        "        except SyntaxError:sys.exit(88)\n"
        "        ast_stmts+=sum(isinstance(n,ast.stmt) for n in ast.walk(tree))\n"
        "        defined_symbols+=sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) for n in ast.walk(tree))\n"
        "    elif path.endswith('.json'):\n"
        "        try:json.loads(content)\n"
        "        except ValueError:sys.exit(89)\n"
        "        json_docs+=1\n"
        "    pathlines=content.splitlines()\n"
        "    nonempty=next((i for i,line in enumerate(pathlines,1) if line.strip()),None)\n"
        "    if nonempty is not None:\n"
        "        revision_suffix=(':'+binding['base_sha']) if status=='D' else ''\n"
        "        refs.append(path+revision_suffix+':L'+str(nonempty))\n"
        "    paths.append(path)\n"
        "if len(paths)!=len(changed) or not refs:sys.exit(90)\n"
        "axes=['contracts_correctness','regression_compatibility','tests_negative_cases','security_authority_concurrency','adversarial_countercheck','additional_adversarial_probe']\n"
        "focus={'contracts_correctness':'interface and contract','regression_compatibility':'compatibility regression','tests_negative_cases':'negative and failure-path','security_authority_concurrency':'security authority and concurrency','adversarial_countercheck':'adversarial countercheck','additional_adversarial_probe':'additional threat probe'}[axis]\n"
        "source_digest=hashlib.sha256(delta.stdout).hexdigest()\n"
        "label=refs[axes.index(axis)%len(refs)]\n"
        "summary=('Server-executed read-only '+focus+' source inspection at exact head '+binding['head_sha'][:12]+' and raw delta '+source_digest[:12]+': '+str(len(changed))+' changed Git paths, '+str(len(paths))+' inspected text paths, '+str(ast_stmts)+' parsed Python statement nodes, '+str(defined_symbols)+' defined symbols, and '+str(json_docs)+' parsed JSON contracts; distinct fixed unittest suite '+suite+' succeeded. Static inspections do not rule out all semantic bugs.')\n"
        "measurement={'changed_paths':len(changed),'inspected_paths':len(paths),'python_statements':ast_stmts,'defined_symbols':defined_symbols,'json_contracts':json_docs}\n"
        "report={'schema_version':1,'kind':'grabowski_trusted_source_inspection_v1','axis':axis,'binding_sha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest(),'source_raw_diff_sha256':source_digest,'method_kind':'deterministic-source-inspection-and-isolated-tests','summary':summary,'evidence_refs':[label],'material_findings':0,'measurements':measurement}\n"
        "sys.stdout.buffer.write(b'\\n'+b'grabowski-phase-source-inspection-v1:'+json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()+b'\\n')\n"
    )




def observed_phase_report(
    output: bytes, *, binding: dict[str, Any], axis: str,
) -> dict[str, Any]:
    """Recover the report emitted by the trusted *outer* worker, not its test child.

    The fixed worker appends exactly one canonical marker after successful
    tests and the source inspection. The caller cannot provide a replacement
    summary and have the issuer silently sign that prose.
    """
    if not isinstance(output, bytes) or len(output) > MAX_OUTPUT:
        raise ReviewExecutionRejected("semantic task output invalid")
    needle = b"\n" + PHASE_OBSERVATION_PREFIX
    at = output.rfind(needle)
    if at < 0 or not output.endswith(b"\n"):
        raise ReviewExecutionRejected("server-observed source review report absent")
    data = output[at + len(needle): -1]
    if not data or len(data) > 16384 or b"\n" in data:
        raise ReviewExecutionRejected("server-observed source review report malformed")
    try:
        decoded = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise ReviewExecutionRejected("server-observed source review report invalid") from exc
    if not isinstance(decoded, dict) or _canonical(decoded) != data:
        raise ReviewExecutionRejected("server-observed source review report not canonical")
    exact = {
        "schema_version", "kind", "axis", "binding_sha256",
        "source_raw_diff_sha256", "method_kind", "summary",
        "evidence_refs", "material_findings", "measurements",
    }
    if (
        set(decoded) != exact
        or decoded["schema_version"] != 1
        or decoded["kind"] != "grabowski_trusted_source_inspection_v1"
        or decoded["axis"] != axis
        or decoded["binding_sha256"] != _digest(binding)
        or decoded["method_kind"] != "deterministic-source-inspection-and-isolated-tests"
    ):
        raise ReviewExecutionRejected("server-observed source report identity drift")
    report_raw = output.split(b"\n", 1)[0]
    prefix = b"source_raw_diff_sha256:"
    raw = report_raw[len(prefix):].decode("ascii", errors="replace") if report_raw.startswith(prefix) else ""
    if decoded["source_raw_diff_sha256"] != raw or SHA256.fullmatch(raw) is None:
        raise ReviewExecutionRejected("server-observed source delta report mismatch")
    measures = decoded["measurements"]
    names = {
        "changed_paths", "inspected_paths", "python_statements",
        "defined_symbols", "json_contracts",
    }
    if (
        not isinstance(measures, dict)
        or set(measures) != names
        or any(type(value) is not int or value < 0 for value in measures.values())
        or measures["changed_paths"] < 1
        or measures["inspected_paths"] < 1
        or measures["inspected_paths"] != measures["changed_paths"]
    ):
        raise ReviewExecutionRejected("server-observed source inspection not substantive")
    summary = decoded["summary"]
    refs = decoded["evidence_refs"]
    if (
        not isinstance(summary, str)
        or len(" ".join(summary.split())) < 80
        or not isinstance(refs, list)
        or not 1 <= len(refs) <= MAX_REFERENCES
        or decoded["material_findings"] != 0
    ):
        raise ReviewExecutionRejected("server-observed source inspection report invalid")
    return {"summary": summary, "evidence_refs": refs, "material_findings": 0}

def _verified_sandbox_command(record: dict[str, Any], task: dict[str, Any]) -> None:
    """Verify the *actual* server task command hash and its no-write sandbox.

    A record with a signed isolation_sha256 but no bound argv is not evidence
    of isolation. Every mount/namespace flag is enumerated; later writable
    mount overrides and arbitrary commands are rejected.
    """
    command = record.get("sandbox_argv")
    if (
        not isinstance(command, list) or any(not isinstance(item, str) for item in command)
        or len(command) < 21
    ):
        raise ReviewExecutionRejected("self-review sandbox argv not observed")
    suite = METHOD_TEST_SUITE.get(record.get("axis"))
    worktree = record.get("worktree_path")
    if (
        suite is None or not isinstance(worktree, str)
        or not worktree.startswith("/") or ".." in Path(worktree).parts
        or _BWRAP_NIX.fullmatch(command[0]) is None
    ):
        raise ReviewExecutionRejected("self-review sandbox method/worktree invalid")
    prefix = [command[0], *_sandbox_bwrap_flags(worktree), "--"]
    binding = record.get("binding")
    # -I prevents untrusted PR-root json.py/ast.py/subprocess.py shadowing.
    tail = ["-I", "-B", "-c", trusted_phase_source(binding, record["axis"], worktree)]
    if (
        command[:len(prefix)] != prefix
        or len(command) != len(prefix) + 1 + len(tail)
        or _PYTHON_NIX.fullmatch(command[len(prefix)]) is None
        or command[len(prefix) + 1:] != tail
    ):
        raise ReviewExecutionRejected("self-review sandbox authority/argv invalid")
    argv_sha256 = hashlib.sha256(
        json.dumps(command, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if task.get("argv_sha256") != argv_sha256:
        raise ReviewExecutionRejected("self-review sandbox command differs from task origin")
    expected_isolation = _digest({
        "argv_sha256": argv_sha256,
        "isolation_policy": "bwrap-readonly-no-net-v1",
        "axis": record.get("axis"),
    })
    if record.get("isolation_sha256") != expected_isolation:
        raise ReviewExecutionRejected("self-review signed isolation binding invalid")


def _verify_task_capture(
    record: dict[str, Any],
    original_output: bytes,
    *,
    capture_root: Path,
) -> None:
    """Require signed output bytes to match the retained server task capture.

    A signature over an arbitrary .out file is not execution provenance.
    Both the task's private managed output directory and immutable completed
    task observation must match before its bytes can count as a review PASS.
    """
    task = record["task"]
    task_id = task["id"]
    root_fd = _private_dir(capture_root)
    try:
        directory = f".grabowski-task-output-{task_id}-a1"
        if not re.fullmatch(r"\.grabowski-task-output-[0-9a-f]{24}-a1", directory):
            raise ReviewExecutionRejected("task output directory identity invalid")
        dir_fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            folder = os.fstat(dir_fd)
            if (
                not stat.S_ISDIR(folder.st_mode)
                or folder.st_uid != os.getuid()
                or stat.S_IMODE(folder.st_mode) != 0o700
            ):
                raise ReviewExecutionRejected("task capture directory authority invalid")
            stdout = _private_read(dir_fd, "stdout.log", limit=MAX_OUTPUT)
            stderr = _private_read(dir_fd, "stderr.log", limit=MAX_OUTPUT, allow_empty=True)
        finally:
            os.close(dir_fd)
    finally:
        os.close(root_fd)
    raw = record.get("source_raw_diff_sha256")
    if (
        not isinstance(raw, str) or SHA256.fullmatch(raw) is None
        or not original_output.startswith(b"source_raw_diff_sha256:" + raw.encode() + b"\n")
    ):
        raise ReviewExecutionRejected("signed review task raw diff does not match execution")
    # The trusted inline worker explicitly sends the unittest transcript to
    # stdout. Reject any unexpected stderr or truncated/mutated capture.
    if stderr or stdout != original_output:
        raise ReviewExecutionRejected("signed self-review output differs from server task capture")


def _task_outcome(
    record: dict[str, Any], outcomes: Path, observed_output: bytes,
    *, capture_root: Path = CAPTURE_ROOT,
) -> None:
    task = record.get("task")
    if not isinstance(task, dict) or set(task) != {
        "id", "unit", "argv_sha256", "lifecycle_receipt_sha256",
    }:
        raise ReviewExecutionRejected("self-review task origin missing")
    task_id = task["id"]
    if not isinstance(task_id, str) or not re.fullmatch(r"[a-f0-9]{24}", task_id):
        raise ReviewExecutionRejected("self-review task id invalid")
    fd = _private_dir(outcomes)
    try:
        raw = _private_read(fd, task_id + ".json", limit=MAX_RECEIPT)
    finally:
        os.close(fd)
    try:
        payload = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ReviewExecutionRejected("task lifecycle receipt JSON invalid") from exc
    if not isinstance(payload, dict):
        raise ReviewExecutionRejected("task lifecycle receipt shape invalid")
    provided = payload.get("receipt_sha256")
    without = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if (
        not isinstance(provided, str)
        or not SHA256.fullmatch(provided)
        or provided != _digest(without)
        or provided != task["lifecycle_receipt_sha256"]
    ):
        raise ReviewExecutionRejected("task lifecycle receipt digest not authentic")
    if (
        payload.get("task_id") != task_id
        or payload.get("state") != "completed"
        or payload.get("unit") != task["unit"]
        or payload.get("argv_sha256") != task["argv_sha256"]
        or payload.get("attempt") != 1
        or payload.get("execution_backend") != "systemd-user"
        or payload.get("systemd_scope") != "user"
        or not isinstance(payload.get("observation"), dict)
    ):
        raise ReviewExecutionRejected("self-review task execution identity mismatch")
    observation = payload["observation"]
    props = observation.get("properties")
    if (
        observation.get("state") != "completed"
        or not isinstance(props, dict)
        or props.get("Result") != "success"
        or props.get("ExecMainStatus") != "0"
    ):
        raise ReviewExecutionRejected("self-review server task completion not confirmed")
    _verified_sandbox_command(record, task)
    _verify_task_capture(record, observed_output, capture_root=capture_root)


def _source_reference(
    ref: str,
    *,
    head: str,
    repository: Path,
    read_source: Callable[[str, str], bytes] | None,
    base: str | None = None,
) -> None:
    match = REF.fullmatch(ref) if isinstance(ref, str) else None
    if match is None or ".." in Path(match["path"]).parts:
        raise ReviewExecutionRejected("unresolvable self-review evidence reference")
    chosen_revision = match["source_revision"] or head
    if chosen_revision != head and (base is None or chosen_revision != base):
        raise ReviewExecutionRejected("self-review source reference revision not bound")
    first = int(match["start"])
    last = int(match["end"] or match["start"])
    if first > last or last - first > 1000:
        raise ReviewExecutionRejected("self-review evidence range invalid")
    if read_source is not None:
        data = read_source(chosen_revision, match["path"])
    else:
        # Git blob SHA identities are content-addressed. Refuse oversized
        # content *before* spawning a process that could buffer its contents.
        target = f"{chosen_revision}:{match['path']}"
        try:
            size = subprocess.run(
                ["git", "--no-replace-objects", "-C", str(repository),
                 "cat-file", "-s", target],
                capture_output=True, timeout=15, check=False,
            )
            if (
                size.returncode != 0 or len(size.stdout) > 20
                or not size.stdout.strip().isdigit()
            ):
                raise ReviewExecutionRejected("self-review source blob size unavailable")
            expected_bytes = int(size.stdout.strip())
            if expected_bytes > MAX_SOURCE_BLOB:
                raise ReviewExecutionRejected("self-review referenced file over budget")
            proc = subprocess.run(
                ["git", "--no-replace-objects", "-C", str(repository),
                 "show", target],
                capture_output=True, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReviewExecutionRejected("self-review Git evidence unavailable") from exc
        if proc.returncode != 0 or len(proc.stdout) != expected_bytes:
            raise ReviewExecutionRejected("self-review referenced file unavailable")
        data = proc.stdout
    if not isinstance(data, bytes) or len(data) > MAX_SOURCE_BLOB or b"\x00" in data:
        raise ReviewExecutionRejected("self-review referenced file is not reviewable text")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ReviewExecutionRejected("self-review referenced text invalid") from exc
    if last > len(lines) or not any(lines[first - 1:last]):
        raise ReviewExecutionRejected("self-review evidence range not present")


class FirstPartyReviewAbsent(ReviewExecutionRejected):
    """No first-party session is bound to this review batch."""


def authenticated_first_party_issuer(
    connector_id: Any, evidence: Any, *, expected_tool: str,
) -> dict[str, Any]:
    """Project consumed signed-ingress evidence into a storable issuer receipt.

    This function accepts only the result of the server's one-call assertion
    consumer.  MCP tool schemas never expose an ``issuer`` argument, so caller
    JSON cannot select or replace this value.
    """
    if (
        not isinstance(connector_id, str)
        or FIRST_PARTY_CONNECTOR_RE.fullmatch(connector_id) is None
        # Other enrolled read/write connectors are not the primary operator.
        or connector_id != "primary"
        or expected_tool not in {
            FIRST_PARTY_TOOL_START, FIRST_PARTY_TOOL_READ,
            FIRST_PARTY_TOOL_SUBMIT,
        }
        or not isinstance(evidence, dict)
        or evidence.get("state") != "consumed"
        or evidence.get("single_use") is not True
        or evidence.get("transport_mode") != "signed-one-call-v1"
        or evidence.get("client_scope_kind") != "connector_capability"
        or evidence.get("tool_name") != expected_tool
    ):
        raise ReviewExecutionRejected("authenticated controller issuer absent")
    required_hashes = (
        "client_scope_sha256", "runtime_binding_sha256", "arguments_sha256",
        "consumption_receipt_sha256",
    )
    if any(
        not isinstance(evidence.get(name), str)
        or SHA256.fullmatch(evidence[name]) is None
        for name in required_hashes
    ):
        raise ReviewExecutionRejected("authenticated controller issuer malformed")
    request_id = evidence.get("request_id")
    if not isinstance(request_id, str) or ID.fullmatch(request_id) is None:
        raise ReviewExecutionRejected("authenticated controller request identity invalid")
    return {
        "schema_version": 1,
        "kind": FIRST_PARTY_ISSUER_KIND,
        "connector_id": connector_id,
        "client_scope_sha256": evidence["client_scope_sha256"],
        "runtime_binding_sha256": evidence["runtime_binding_sha256"],
        "request_id": request_id,
        "tool_name": expected_tool,
        "arguments_sha256": evidence["arguments_sha256"],
        "consumption_receipt_sha256": evidence["consumption_receipt_sha256"],
    }


def _validate_first_party_issuer(
    value: Any, *, expected_tool: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "kind", "connector_id", "client_scope_sha256",
        "runtime_binding_sha256", "request_id", "tool_name",
        "arguments_sha256", "consumption_receipt_sha256",
    }:
        raise ReviewExecutionRejected("first-party issuer receipt shape invalid")
    if value.get("schema_version") != 1 or value.get("kind") != FIRST_PARTY_ISSUER_KIND:
        raise ReviewExecutionRejected("first-party issuer receipt identity invalid")
    return authenticated_first_party_issuer(
        value["connector_id"],
        {
            "state": "consumed", "single_use": True,
            "transport_mode": "signed-one-call-v1",
            "client_scope_kind": "connector_capability",
            **{key: value[key] for key in (
                "client_scope_sha256", "runtime_binding_sha256", "request_id",
                "tool_name", "arguments_sha256", "consumption_receipt_sha256",
            )},
        },
        expected_tool=expected_tool,
    )


def _first_party_principal(issuer: dict[str, Any]) -> dict[str, str]:
    return {
        "connector_id": issuer["connector_id"],
        "client_scope_sha256": issuer["client_scope_sha256"],
    }


def _ensure_private_state_directory(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReviewExecutionRejected("first-party review state directory unsafe")


def _create_private_bytes(path: Path, data: bytes) -> None:
    if not isinstance(data, bytes):
        raise ReviewExecutionRejected("first-party review record bytes invalid")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _first_party_lock(root: Path, *, read_only: bool = False) -> int:
    if read_only:
        fd = _private_dir(root)
        os.close(fd)
    else:
        _ensure_private_state_directory(root)
    path = root / ".lock"
    descriptor = os.open(
        path,
        (os.O_RDONLY if read_only else os.O_RDWR | os.O_CREAT) | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise ReviewExecutionRejected("first-party review state lock unsafe")
    fcntl.flock(descriptor, fcntl.LOCK_SH if read_only else fcntl.LOCK_EX)
    return descriptor


def _release_first_party_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _private_signing_key(path: Path) -> None:
    metadata = path.lstat()
    parent = path.parent.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise ReviewExecutionRejected("first-party review signing key unsafe")


def _sign_server_record(material: bytes, *, key: Path, signers: Path) -> bytes:
    _private_signing_key(key)
    try:
        result = subprocess.run(
            [
                _trusted_ssh_keygen(), "-Y", "sign", "-f", str(key),
                "-n", NAMESPACE,
            ],
            input=material, capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewExecutionRejected("first-party review signer unavailable") from exc
    if result.returncode != 0:
        raise ReviewExecutionRejected("first-party review signature failed")
    _check_signature(material, result.stdout, signers)
    return result.stdout


def _rename_private_record(parent_fd: int, staged: str, destination: str) -> None:
    # Keep the standalone signature verifier independent of the MCP operator.
    # Linux renameat2(RENAME_NOREPLACE) publishes once without a hardlink window.
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise ReviewExecutionRejected("atomic record publication unavailable") from exc
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(staged), parent_fd, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise ReviewExecutionRejected("first-party record publication failed") from OSError(error, os.strerror(error))


def _publish_private_record(path: Path, data: bytes) -> None:
    """Publish a complete signed record without replacing an existing one."""

    parent_fd = _private_dir(path.parent)
    staged = ".signed-record-stage-" + secrets.token_hex(16)
    try:
        descriptor = os.open(
            staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent_fd,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # A hardlink-based publish would leave st_nlink == 2 after a crash.
        # Rename also keeps unfinished staging files outside the *.json history.
        _rename_private_record(parent_fd, staged, path.name)
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(staged, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_fd)


def _write_signed_record(
    path: Path, record: dict[str, Any], *, key: Path, signers: Path,
    max_bytes: int = MAX_RECEIPT, atomic: bool = False,
) -> tuple[str, str]:
    material = _canonical(record)
    if len(material) > max_bytes:
        raise ReviewExecutionRejected("first-party review receipt over budget")
    signature = _sign_server_record(material, key=key, signers=signers)
    if atomic:
        if len(signature) > MAX_RECORD_SIGNATURE:
            raise ReviewExecutionRejected("first-party record signature over budget")
        _publish_private_record(path, _canonical({
            "kind": SIGNED_RECORD_ENVELOPE_KIND,
            "record": record, "signature": signature.decode("ascii"),
        }))
    else:
        # Session creation still publishes its complete staged directory.
        # Retain the existing JSON/SIG layout for its batch-index bindings.
        _create_private_bytes(path, material)
        _create_private_bytes(path.with_suffix(".sig"), signature)
    return hashlib.sha256(material).hexdigest(), hashlib.sha256(signature).hexdigest()


def _read_signed_record(
    path: Path, *, signers: Path, root_owned_signers: bool,
    max_bytes: int = MAX_RECEIPT,
) -> dict[str, Any]:
    parent_fd = _private_dir(path.parent)
    try:
        material = _private_read(
            parent_fd, path.name, limit=max_bytes + 2 * MAX_RECORD_SIGNATURE + 256,
        )
        stored = _json_record(material)
        if stored.get("kind") == SIGNED_RECORD_ENVELOPE_KIND:
            if (
                set(stored) != {"kind", "record", "signature"}
                or not isinstance(stored["record"], dict)
                or not isinstance(stored["signature"], str)
                or not stored["signature"].isascii()
                or not 0 < len(stored["signature"]) <= MAX_RECORD_SIGNATURE
            ):
                raise ReviewExecutionRejected("first-party signed record envelope invalid")
            material = _canonical(stored["record"])
            signature = stored["signature"].encode("ascii")
        else:
            # Incomplete legacy pairs remain fail-closed, including old REJECTs.
            signature = _private_read(
                parent_fd, path.with_suffix(".sig").name, limit=MAX_RECORD_SIGNATURE,
            )
        if len(material) > max_bytes:
            raise ReviewExecutionRejected("first-party review receipt over budget")
    finally:
        os.close(parent_fd)
    _check_signature(
        material, signature,
        _allowed_signers(signers, root_owned=root_owned_signers),
    )
    return _json_record(material)


def _first_party_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReviewExecutionRejected("first-party review binding absent")
    expected = {
        "repo", "pr", "base_sha", "head_sha", "diff_sha256",
        "review_batch_id", "review_purpose",
    }
    if value.get("review_purpose") == "post_merge_release":
        expected.add("release_binding")
    frozen = value.get("review_purpose") == "frozen_candidate"
    if frozen:
        expected.add("candidate_binding")
    if (
        set(value) != expected
        or not isinstance(value.get("repo"), str)
        or re.fullmatch(r"heimgewebe/[A-Za-z0-9_.-]+", value["repo"]) is None
        or type(value.get("pr")) is not int or (value["pr"] != 0 if frozen else value["pr"] <= 0)
        or any(
            not isinstance(value.get(name), str)
            or SHA40.fullmatch(value[name]) is None
            for name in ("base_sha", "head_sha")
        )
        or not isinstance(value.get("diff_sha256"), str)
        or SHA256.fullmatch(value["diff_sha256"]) is None
        or not isinstance(value.get("review_batch_id"), str)
        or ID.fullmatch(value["review_batch_id"]) is None
        or value.get("review_purpose") not in {"pull_request", "post_merge_release", "frozen_candidate"}
    ):
        raise ReviewExecutionRejected("first-party review binding invalid")
    if frozen:
        candidate = value["candidate_binding"]
        if (
            not isinstance(candidate, dict)
            or not isinstance(candidate.get("workspace_id"), str)
            or any(candidate.get(k) != value[k] for k in (
                "repo", "base_sha", "head_sha", "diff_sha256",
            ))
            or type(candidate.get("dirty")) is not bool
            or not isinstance(candidate.get("candidate"), dict)
            or candidate["candidate"].get("workspace_id") != candidate["workspace_id"]
        ):
            raise ReviewExecutionRejected("first-party frozen Candidate binding invalid")
    if value["review_purpose"] == "post_merge_release":
        release = value.get("release_binding")
        if (
            not isinstance(release, dict)
            or set(release) != {"serving_release_id", "serving_tree", "target_tree"}
            or not isinstance(release.get("serving_release_id"), str)
            or not release["serving_release_id"]
            or any(
                not isinstance(release.get(name), str)
                or SHA40.fullmatch(release[name]) is None
                for name in ("serving_tree", "target_tree")
            )
        ):
            raise ReviewExecutionRejected("first-party release binding invalid")
    return dict(value)


def _git_read(
    repository: Path, arguments: list[str], *, maximum: int, timeout: int = 30,
) -> bytes:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repository), *arguments],
            capture_output=True, timeout=timeout, check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewExecutionRejected("first-party review Git read unavailable") from exc
    if result.returncode != 0 or len(result.stdout) > maximum:
        raise ReviewExecutionRejected("first-party review Git read failed or over budget")
    return result.stdout


def _first_party_diff(repository: Path, binding: dict[str, Any]) -> bytes:
    if binding.get("review_purpose") == "frozen_candidate":
        from grabowski_agent_role import read_bound_review_input_artifact
        from grabowski_agent_workspace import _ensure_root
        artifact = binding["candidate_binding"]["patch"]
        return read_bound_review_input_artifact(
            str(_ensure_root(create=False)), artifact["path"], artifact["sha256"],
        )
    return _git_read(
        repository,
        [
            "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
            "--ignore-submodules=none", "--unified=3",
            binding["base_sha"], binding["head_sha"], "--",
        ],
        maximum=FIRST_PARTY_MAX_DIFF_BYTES,
        timeout=60,
    )


def _first_party_changed_paths(
    repository: Path, binding: dict[str, Any],
) -> list[str]:
    if binding.get("review_purpose") == "frozen_candidate":
        return list(binding["candidate_binding"]["changed_paths"])
    raw = _git_read(
        repository,
        [
            "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
            "--ignore-submodules=none", "--name-only", "-z",
            binding["base_sha"], binding["head_sha"], "--",
        ],
        maximum=FIRST_PARTY_MAX_DIFF_BYTES,
        timeout=60,
    )
    if not raw or not raw.endswith(b"\x00"):
        raise ReviewExecutionRejected("first-party review changed paths absent")
    try:
        paths = [item.decode("utf-8") for item in raw[:-1].split(b"\x00")]
    except UnicodeError as exc:
        raise ReviewExecutionRejected("first-party changed path encoding invalid") from exc
    if (
        not 1 <= len(paths) <= 256
        or len(paths) != len(set(paths))
        or any(
            not path or len(path) > 512 or ".." in Path(path).parts
            or re.fullmatch(r"[A-Za-z0-9_.@+/-]+", path) is None
            for path in paths
        )
    ):
        raise ReviewExecutionRejected("first-party changed path set invalid")
    return paths


def _read_private_json(path: Path) -> dict[str, Any]:
    fd = _private_dir(path.parent)
    try:
        raw = _private_read(fd, path.name, limit=MAX_RECEIPT)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_semantic_json_object)
    except (ValueError, UnicodeError) as exc:
        raise ReviewExecutionRejected("private workspace JSON invalid") from exc
    if not isinstance(value, dict):
        raise ReviewExecutionRejected("private workspace JSON must be an object")
    return value


def _first_party_source_blob(repository: Path, binding: dict[str, Any], path: str, revision: str) -> bytes:
    if binding.get("review_purpose") == "frozen_candidate" and revision == "head":
        from grabowski_agent_role import safe_untracked_file
        from pathlib import PurePosixPath
        target = safe_untracked_file(repository, PurePosixPath(path))
        if target.stat().st_size > MAX_SOURCE_BLOB:
            raise ReviewExecutionRejected("first-party Candidate source over budget")
        return target.read_bytes()
    chosen = binding["base_sha"] if revision == "base" else binding["head_sha"]
    return _git_read(repository, ["show", chosen + ":" + path], maximum=MAX_SOURCE_BLOB)


def _assert_plan_source(plan: dict[str, Any]) -> tuple[dict[str, Any], Path, str]:
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise ReviewExecutionRejected("first-party review plan invalid")
    kind = plan.get("kind")
    if kind == "grabowski_self_review_execution_plan":
        if not isinstance(plan.get("tasks"), dict) or set(plan["tasks"]) != set(REQUIRED_AXES):
            raise ReviewExecutionRejected("first-party review plan invalid")
    elif kind == "grabowski_first_party_review_plan":
        if "tasks" in plan:
            raise ReviewExecutionRejected("first-party direct plan contains technical tasks")
    else:
        raise ReviewExecutionRejected("first-party review plan invalid")
    binding = _first_party_binding(plan.get("binding"))
    worktree_raw = plan.get("worktree")
    source_raw = plan.get("source_raw_diff_sha256")
    if (
        not isinstance(worktree_raw, str) or not worktree_raw.startswith("/")
        or ".." in Path(worktree_raw).parts
        or not isinstance(source_raw, str) or SHA256.fullmatch(source_raw) is None
    ):
        raise ReviewExecutionRejected("first-party review plan source invalid")
    from grabowski_self_review_producer import _current_source
    worktree = Path(worktree_raw).resolve(strict=True)
    if _current_source(worktree, binding) != source_raw:
        raise ReviewExecutionRejected("first-party review plan source drift")
    return binding, worktree, source_raw


def start_first_party_review_session(
    plan: dict[str, Any], issuer: dict[str, Any], *,
    root: Path = FIRST_PARTY_REVIEW_ROOT,
    key: Path = SIGNING_KEY,
    signers: Path = TRUSTED_SIGNERS,
    root_owned_signers: bool = True,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Create the only authenticated controller session for one review batch."""
    authenticated = _validate_first_party_issuer(
        issuer, expected_tool=FIRST_PARTY_TOOL_START,
    )
    signers = _allowed_signers(signers, root_owned=root_owned_signers)
    binding, worktree, source_raw = _assert_plan_source(plan)
    diff = _first_party_diff(worktree, binding)
    canonical_diff_sha256 = hashlib.sha256(diff).hexdigest()
    changed_paths = _first_party_changed_paths(worktree, binding)
    observed_at = int(time.time()) if now_unix is None else now_unix
    if type(observed_at) is not int or observed_at < 0:
        raise ReviewExecutionRejected("first-party session observation time invalid")
    session_id = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    session = {
        "schema_version": 1,
        "kind": FIRST_PARTY_SESSION_KIND,
        "session_id": session_id,
        "session_nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        "binding": binding,
        "binding_sha256": _digest(binding),
        "worktree": str(worktree),
        "source_raw_diff_sha256": source_raw,
        "canonical_diff_sha256": canonical_diff_sha256,
        "changed_paths": changed_paths,
        "issuer_principal": _first_party_principal(authenticated),
        "start_issuer": authenticated,
        "created_at_unix": observed_at,
        "expires_at_unix": observed_at + FIRST_PARTY_SESSION_TTL_SECONDS,
    }
    lock = _first_party_lock(root)
    try:
        batches = root / "batches"
        sessions = root / "sessions"
        _ensure_private_state_directory(batches)
        _ensure_private_state_directory(sessions)
        index_path = batches / (binding["review_batch_id"] + ".json")
        if index_path.exists():
            raise ReviewExecutionRejected("first-party review batch already has a session")
        session_root = sessions / session_id
        # Incomplete starts (including crash leftovers) must stay outside the
        # authenticated history scanned under sessions/.
        with tempfile.TemporaryDirectory(prefix=".session-stage-", dir=root) as stage:
            staged_root = Path(stage) / session_id
            _ensure_private_state_directory(staged_root)
            _ensure_private_state_directory(staged_root / "reads")
            _ensure_private_state_directory(staged_root / "axes")
            receipt_sha256, signature_sha256 = _write_signed_record(
                staged_root / "session.json", session, key=key, signers=signers,
            )
            _read_signed_record(
                staged_root / "session.json", signers=signers,
                root_owned_signers=root_owned_signers,
            )
            if session_root.exists() or session_root.is_symlink():
                raise ReviewExecutionRejected("first-party review session already exists")
            staged_root.rename(session_root)
        index = {
            "schema_version": 1,
            "kind": "grabowski_first_party_review_batch_index_v1",
            "review_batch_id": binding["review_batch_id"],
            "session_id": session_id,
            "binding_sha256": session["binding_sha256"],
            "session_receipt_sha256": receipt_sha256,
            "session_signature_sha256": signature_sha256,
        }
        _create_private_bytes(index_path, _canonical(index))
    finally:
        _release_first_party_lock(lock)
    return {
        "status": "review_session_started",
        "review_session_id": session_id,
        "session_nonce": nonce,
        "review_batch_id": binding["review_batch_id"],
        "head_sha": binding["head_sha"],
        "canonical_diff_sha256": session["canonical_diff_sha256"],
        "required_axes": list(REQUIRED_AXES),
        "expires_at_unix": session["expires_at_unix"],
        "does_not_establish": ["source_inspection", "semantic_review", "review_pass"],
    }


def _load_first_party_session(
    session_id: str, nonce: str, *, root: Path, signers: Path,
    root_owned_signers: bool, now_unix: int, require_fresh: bool,
) -> tuple[dict[str, Any], Path]:
    if (
        not isinstance(session_id, str) or ID.fullmatch(session_id) is None
        or not isinstance(nonce, str) or ID.fullmatch(nonce) is None
    ):
        raise ReviewExecutionRejected("first-party session identity invalid")
    session_root = root / "sessions" / session_id
    record = _read_signed_record(
        session_root / "session.json", signers=signers,
        root_owned_signers=root_owned_signers,
    )
    if (
        set(record) != {
            "schema_version", "kind", "session_id", "session_nonce_sha256",
            "binding", "binding_sha256", "worktree", "source_raw_diff_sha256",
            "canonical_diff_sha256", "changed_paths", "issuer_principal",
            "start_issuer", "created_at_unix", "expires_at_unix",
        }
        or record.get("schema_version") != 1
        or record.get("kind") != FIRST_PARTY_SESSION_KIND
        or record.get("session_id") != session_id
        or record.get("session_nonce_sha256")
        != hashlib.sha256(nonce.encode("ascii")).hexdigest()
        or record.get("binding_sha256") != _digest(_first_party_binding(record.get("binding")))
        or not isinstance(record.get("changed_paths"), list)
        or not isinstance(record.get("issuer_principal"), dict)
        or _validate_first_party_issuer(
            record.get("start_issuer"), expected_tool=FIRST_PARTY_TOOL_START,
        ) != record.get("start_issuer")
    ):
        raise ReviewExecutionRejected("first-party session receipt invalid")
    if record["issuer_principal"] != _first_party_principal(record["start_issuer"]):
        raise ReviewExecutionRejected("first-party session principal mismatch")
    if (
        type(record.get("created_at_unix")) is not int
        or type(record.get("expires_at_unix")) is not int
        or record["expires_at_unix"] - record["created_at_unix"]
        != FIRST_PARTY_SESSION_TTL_SECONDS
        or (require_fresh and now_unix > record["expires_at_unix"])
    ):
        raise ReviewExecutionRejected("first-party review session expired")
    return record, session_root


def _assert_first_party_source_current(session: dict[str, Any]) -> Path:
    binding = session["binding"]
    worktree = Path(session["worktree"])
    from grabowski_self_review_producer import _current_source
    if _current_source(worktree, binding) != session["source_raw_diff_sha256"]:
        raise ReviewExecutionRejected("first-party review source revision drift")
    diff = _first_party_diff(worktree, binding)
    if hashlib.sha256(diff).hexdigest() != session["canonical_diff_sha256"]:
        raise ReviewExecutionRejected("first-party canonical diff drift")
    return worktree


def _issuer_matches_session(
    issuer: dict[str, Any], session: dict[str, Any], *, expected_tool: str,
) -> dict[str, Any]:
    authenticated = _validate_first_party_issuer(issuer, expected_tool=expected_tool)
    if _first_party_principal(authenticated) != session["issuer_principal"]:
        raise ReviewExecutionRejected("first-party issuer crossed controller session")
    return authenticated


def record_first_party_source_read(
    session_id: str, nonce: str, axis: str, read_kind: str,
    path: str, revision: str, start_line: int, end_line: int,
    issuer: dict[str, Any], *,
    root: Path = FIRST_PARTY_REVIEW_ROOT,
    key: Path = SIGNING_KEY,
    signers: Path = TRUSTED_SIGNERS,
    root_owned_signers: bool = True,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Read immutable Git bytes and persist exactly what the controller received."""
    observed_at = int(time.time()) if now_unix is None else now_unix
    session, session_root = _load_first_party_session(
        session_id, nonce, root=root, signers=signers,
        root_owned_signers=root_owned_signers, now_unix=observed_at,
        require_fresh=True,
    )
    authenticated = _issuer_matches_session(
        issuer, session, expected_tool=FIRST_PARTY_TOOL_READ,
    )
    signers = _allowed_signers(signers, root_owned=root_owned_signers)
    if axis not in REQUIRED_AXES:
        raise ReviewExecutionRejected("first-party source read axis invalid")
    worktree = _assert_first_party_source_current(session)
    binding = session["binding"]
    source_ref: str | None = None
    diff_total_lines: int | None = None
    if read_kind == "diff":
        if (
            path != "" or revision != "head"
            or type(start_line) is not int or type(end_line) is not int
            or start_line < 1 or end_line < start_line
            or end_line - start_line + 1 > FIRST_PARTY_MAX_READ_LINES
        ):
            raise ReviewExecutionRejected("first-party canonical diff read shape invalid")
        try:
            lines = _first_party_diff(worktree, binding).decode("utf-8").splitlines(keepends=True)
        except UnicodeError as exc:
            raise ReviewExecutionRejected("first-party canonical diff is not reviewable text") from exc
        diff_total_lines = len(lines)
        if end_line > diff_total_lines:
            raise ReviewExecutionRejected("first-party canonical diff range invalid")
        data = "".join(lines[start_line - 1:end_line]).encode("utf-8")
        if not data or len(data) > FIRST_PARTY_MAX_READ_BYTES:
            raise ReviewExecutionRejected("first-party canonical diff chunk over budget")
    elif read_kind == "source":
        if (
            not isinstance(path, str) or path not in session["changed_paths"]
            or revision not in {"base", "head"}
            or type(start_line) is not int or type(end_line) is not int
            or start_line < 1 or end_line < start_line
            or end_line - start_line + 1 > FIRST_PARTY_MAX_READ_LINES
        ):
            raise ReviewExecutionRejected("first-party source read range invalid")
        chosen = binding["base_sha"] if revision == "base" else binding["head_sha"]
        blob = _first_party_source_blob(worktree, binding, path, revision)
        if b"\x00" in blob:
            raise ReviewExecutionRejected("first-party source read is not text")
        try:
            lines = blob.decode("utf-8").splitlines(keepends=True)
        except UnicodeError as exc:
            raise ReviewExecutionRejected("first-party source read encoding invalid") from exc
        if end_line > len(lines) or not any(line.strip() for line in lines[start_line - 1:end_line]):
            raise ReviewExecutionRejected("first-party source read range absent")
        data = "".join(lines[start_line - 1:end_line]).encode("utf-8")
        if len(data) > FIRST_PARTY_MAX_READ_BYTES:
            raise ReviewExecutionRejected("first-party source read over budget")
        suffix = "" if revision == "head" else ":" + binding["base_sha"]
        source_ref = f"{path}{suffix}:L{start_line}-L{end_line}"
    else:
        raise ReviewExecutionRejected("first-party read kind invalid")
    read_id = secrets.token_hex(16)
    record = {
        "schema_version": 1, "kind": FIRST_PARTY_READ_KIND,
        "read_id": read_id, "session_id": session_id,
        "binding_sha256": session["binding_sha256"], "axis": axis,
        "read_kind": read_kind, "path": path, "revision": revision,
        "start_line": start_line, "end_line": end_line,
        "source_ref": source_ref, "data_sha256": hashlib.sha256(data).hexdigest(),
        "data_bytes": len(data), "issuer": authenticated,
        "observed_at_unix": observed_at,
    }
    lock = _first_party_lock(root)
    try:
        _assert_first_party_source_current(session)
        reads = session_root / "reads"
        _create_private_bytes(reads / (read_id + ".data"), data)
        _write_signed_record(
            reads / (read_id + ".json"), record, key=key, signers=signers,
            atomic=True,
        )
    finally:
        _release_first_party_lock(lock)
    return {
        "status": "source_read_recorded", "review_session_id": session_id,
        "axis": axis, "read_id": read_id, "read_kind": read_kind,
        "source_ref": source_ref, "content": data.decode("utf-8"),
        "content_sha256": record["data_sha256"],
        **(
            {"diff_total_lines": diff_total_lines,
             "canonical_diff_sha256": session["canonical_diff_sha256"]}
            if read_kind == "diff" else {}
        ),
        "does_not_establish": ["semantic_review", "axis_verdict", "review_pass"],
    }


def _load_first_party_reads(
    session: dict[str, Any], session_root: Path, *,
    signers: Path, root_owned_signers: bool, repository: Path,
) -> list[dict[str, Any]]:
    reads_root = session_root / "reads"
    validation_fd = _private_dir(reads_root)
    os.close(validation_fd)  # Validation only; per-record reads reopen safely.
    records: list[dict[str, Any]] = []
    request_ids: set[str] = {session["start_issuer"]["request_id"]}
    for path in sorted(reads_root.glob("*.json")):
        if FIRST_PARTY_READ_ID_RE.fullmatch(path.stem) is None:
            raise ReviewExecutionRejected("first-party read record name invalid")
        record = _read_signed_record(
            path, signers=signers, root_owned_signers=root_owned_signers,
        )
        issuer = _validate_first_party_issuer(
            record.get("issuer"), expected_tool=FIRST_PARTY_TOOL_READ,
        )
        if (
            set(record) != {
                "schema_version", "kind", "read_id", "session_id",
                "binding_sha256", "axis", "read_kind", "path", "revision",
                "start_line", "end_line", "source_ref", "data_sha256",
                "data_bytes", "issuer", "observed_at_unix",
            }
            or record.get("schema_version") != 1
            or record.get("kind") != FIRST_PARTY_READ_KIND
            or record.get("read_id") != path.stem
            or record.get("session_id") != session["session_id"]
            or record.get("binding_sha256") != session["binding_sha256"]
            or record.get("axis") not in REQUIRED_AXES
            or _first_party_principal(issuer) != session["issuer_principal"]
            or issuer["request_id"] in request_ids
            or type(record.get("observed_at_unix")) is not int
            or not session["created_at_unix"] <= record["observed_at_unix"] <= session["expires_at_unix"]
        ):
            raise ReviewExecutionRejected("first-party read receipt invalid or replayed")
        request_ids.add(issuer["request_id"])
        parent_fd = _private_dir(reads_root)
        try:
            data = _private_read(
                parent_fd, path.stem + ".data", limit=FIRST_PARTY_MAX_DIFF_BYTES,
                allow_empty=True,
            )
        finally:
            os.close(parent_fd)
        if (
            record.get("data_bytes") != len(data)
            or record.get("data_sha256") != hashlib.sha256(data).hexdigest()
        ):
            raise ReviewExecutionRejected("first-party persisted source read changed")
        if record["read_kind"] == "diff":
            try:
                complete_diff = _first_party_diff(repository, session["binding"])
                lines = complete_diff.decode("utf-8").splitlines(keepends=True)
            except UnicodeError as exc:
                raise ReviewExecutionRejected("first-party canonical diff not text") from exc
            first, last = record["start_line"], record["end_line"]
            if (
                record["path"] != "" or record["revision"] != "head"
                or type(first) is not int or type(last) is not int
                or first < 1 or last < first or last > len(lines)
                or last - first + 1 > FIRST_PARTY_MAX_READ_LINES
                or record["source_ref"] is not None
                or hashlib.sha256(complete_diff).hexdigest() != session["canonical_diff_sha256"]
                or data != "".join(lines[first - 1:last]).encode("utf-8")
                or len(data) > FIRST_PARTY_MAX_READ_BYTES
            ):
                raise ReviewExecutionRejected("first-party canonical diff chunk invalid")
        elif record["read_kind"] == "source":
            match = REF.fullmatch(record.get("source_ref", ""))
            chosen = (
                session["binding"]["base_sha"]
                if record["revision"] == "base"
                else session["binding"]["head_sha"]
            )
            if (
                match is None or match["path"] != record["path"]
                or int(match["start"]) != record["start_line"]
                or int(match["end"] or match["start"]) != record["end_line"]
                or chosen != (match["source_revision"] or session["binding"]["head_sha"])
                or record["path"] not in session["changed_paths"]
            ):
                raise ReviewExecutionRejected("first-party source read binding invalid")
            blob = _first_party_source_blob(
                repository, session["binding"], record["path"], record["revision"],
            )
            try:
                lines = blob.decode("utf-8").splitlines(keepends=True)
            except UnicodeError as exc:
                raise ReviewExecutionRejected("first-party source blob invalid") from exc
            expected = "".join(
                lines[record["start_line"] - 1:record["end_line"]]
            ).encode("utf-8")
            if data != expected:
                raise ReviewExecutionRejected("first-party source read bytes mismatch")
        else:
            raise ReviewExecutionRejected("first-party persisted read kind invalid")
        records.append({**record, "_data": data})
    return records


def _read_covers_reference(
    reference: Any, *, axis: str, reads: list[dict[str, Any]],
    binding: dict[str, Any],
) -> bool:
    match = REF.fullmatch(reference) if isinstance(reference, str) else None
    if match is None:
        return False
    revision = match["source_revision"] or binding["head_sha"]
    first = int(match["start"])
    last = int(match["end"] or match["start"])
    return any(
        item["axis"] == axis
        and item["read_kind"] == "source"
        and item["path"] == match["path"]
        and (
            binding.get("review_purpose") != "frozen_candidate"
            or item["revision"] == ("base" if match["source_revision"] else "head")
        )
        and (
            binding["base_sha"] if item["revision"] == "base"
            else binding["head_sha"]
        ) == revision
        and item["start_line"] <= first <= last <= item["end_line"]
        for item in reads
    )


def _substantive_text(value: Any, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and minimum <= len(" ".join(value.split())) <= maximum
    )


def _validate_first_party_report(
    report: Any, *, axis: str, reads: list[dict[str, Any]],
    binding: dict[str, Any], prior_observations: set[str],
) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != {
        "axis", "verdict", "summary", "axis_observations", "evidence_refs",
        "reviewed_risks", "findings",
    }:
        raise ReviewExecutionRejected("first-party axis report shape invalid")
    if report.get("axis") != axis or report.get("verdict") not in {"PASS", "REJECT"}:
        raise ReviewExecutionRejected("first-party axis report verdict invalid")
    if not _substantive_text(report.get("summary"), 160, 8000):
        raise ReviewExecutionRejected("first-party semantic summary inadequate")
    observations = report.get("axis_observations")
    if (
        not isinstance(observations, list) or not 2 <= len(observations) <= 8
        or any(not _substantive_text(item, 80, 2000) for item in observations)
        or len(observations) != len(set(observations))
        or any(item in prior_observations for item in observations)
    ):
        raise ReviewExecutionRejected("first-party axis observations not distinct")
    refs = report.get("evidence_refs")
    if (
        not isinstance(refs, list) or not 2 <= len(refs) <= MAX_REFERENCES
        or len(refs) != len(set(refs))
        or any(not _read_covers_reference(
            item, axis=axis, reads=reads, binding=binding,
        ) for item in refs)
    ):
        raise ReviewExecutionRejected("first-party report lacks observed source references")
    if not any(item["axis"] == axis and item["read_kind"] == "diff" for item in reads):
        raise ReviewExecutionRejected("first-party axis canonical diff was not read")
    risks = report.get("reviewed_risks")
    if not isinstance(risks, list) or not 2 <= len(risks) <= 16:
        raise ReviewExecutionRejected("first-party report requires two reviewed risks")
    risk_names: set[str] = set()
    assessments: set[str] = set()
    material_risk = False
    for risk in risks:
        if (
            not isinstance(risk, dict)
            or set(risk) != {"risk", "assessment", "verdict", "evidence_refs"}
            or not _substantive_text(risk.get("risk"), 20, 500)
            or risk["risk"] in risk_names
            or not _substantive_text(risk.get("assessment"), 80, 3000)
            or risk["assessment"] in assessments
            or risk.get("verdict") not in {"NON_MATERIAL", "MATERIAL"}
            or not isinstance(risk.get("evidence_refs"), list)
            or not 1 <= len(risk["evidence_refs"]) <= MAX_REFERENCES
            or any(not _read_covers_reference(
                item, axis=axis, reads=reads, binding=binding,
            ) for item in risk["evidence_refs"])
        ):
            raise ReviewExecutionRejected("first-party reviewed risk inadequate")
        risk_names.add(risk["risk"])
        assessments.add(risk["assessment"])
        material_risk = material_risk or risk["verdict"] == "MATERIAL"
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > 32:
        raise ReviewExecutionRejected("first-party findings list invalid")
    finding_ids: set[str] = set()
    unresolved = 0
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {
                "id", "severity", "verdict", "summary", "evidence_refs",
            }
            or not isinstance(finding.get("id"), str)
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", finding["id"]) is None
            or finding["id"] in finding_ids
            or finding.get("severity") not in {"low", "medium", "high", "critical"}
            or finding.get("verdict") not in {"RESOLVED", "UNRESOLVED"}
            or not _substantive_text(finding.get("summary"), 80, 3000)
            or not isinstance(finding.get("evidence_refs"), list)
            or not 1 <= len(finding["evidence_refs"]) <= MAX_REFERENCES
            or any(not _read_covers_reference(
                item, axis=axis, reads=reads, binding=binding,
            ) for item in finding["evidence_refs"])
        ):
            raise ReviewExecutionRejected("first-party finding invalid")
        finding_ids.add(finding["id"])
        unresolved += finding["verdict"] == "UNRESOLVED"
    if (
        (report["verdict"] == "PASS" and (material_risk or unresolved))
        or (report["verdict"] == "REJECT" and not (material_risk and unresolved))
    ):
        raise ReviewExecutionRejected("first-party verdict contradicts material findings")
    return json.loads(_canonical(report))


def _load_first_party_axes(
    session: dict[str, Any], session_root: Path, *,
    reads: list[dict[str, Any]], signers: Path, root_owned_signers: bool,
) -> dict[str, dict[str, Any]]:
    axes_root = session_root / "axes"
    validation_fd = _private_dir(axes_root)
    os.close(validation_fd)
    accepted: dict[str, dict[str, Any]] = {}
    observations: set[str] = set()
    summaries: set[str] = set()
    request_ids = {
        session["start_issuer"]["request_id"],
        *(item["issuer"]["request_id"] for item in reads),
    }
    for path in sorted(axes_root.glob("*.json")):
        axis = path.stem
        if axis not in REQUIRED_AXES:
            raise ReviewExecutionRejected("first-party axis receipt name invalid")
        record = _read_signed_record(
            path, signers=signers, root_owned_signers=root_owned_signers,
        )
        issuer = _validate_first_party_issuer(
            record.get("issuer"), expected_tool=FIRST_PARTY_TOOL_SUBMIT,
        )
        if (
            set(record) != {
                "schema_version", "kind", "session_id", "binding_sha256",
                "axis", "report", "report_sha256", "issuer", "submitted_at_unix",
            }
            or record.get("schema_version") != 1
            or record.get("kind") != FIRST_PARTY_AXIS_KIND
            or record.get("session_id") != session["session_id"]
            or record.get("binding_sha256") != session["binding_sha256"]
            or record.get("axis") != axis
            or _first_party_principal(issuer) != session["issuer_principal"]
            or issuer["request_id"] in request_ids
            or record.get("report_sha256") != _digest(record.get("report"))
            or record.get("report", {}).get("summary") in summaries
            or type(record.get("submitted_at_unix")) is not int
            or not session["created_at_unix"] <= record["submitted_at_unix"] <= session["expires_at_unix"]
        ):
            raise ReviewExecutionRejected("first-party axis receipt invalid or replayed")
        request_ids.add(issuer["request_id"])
        report = _validate_first_party_report(
            record["report"], axis=axis, reads=reads,
            binding=session["binding"], prior_observations=observations,
        )
        observations.update(report["axis_observations"])
        summaries.add(report["summary"])
        accepted[axis] = record
    return accepted


def finalize_first_party_candidate(
    session_id: str, nonce: str, issuer: dict[str, Any], *,
    root: Path = FIRST_PARTY_REVIEW_ROOT, key: Path = SIGNING_KEY,
    signers: Path = TRUSTED_SIGNERS, root_owned_signers: bool = True,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Seal an authenticated handoff, only after the ordinary five-axis verifier."""
    now = int(time.time()) if now_unix is None else now_unix
    session, session_root = _load_first_party_session(
        session_id, nonce, root=root, signers=signers,
        root_owned_signers=root_owned_signers, now_unix=now, require_fresh=True,
    )
    authenticated = _issuer_matches_session(issuer, session, expected_tool=FIRST_PARTY_TOOL_SUBMIT)
    binding = session["binding"]
    if binding["review_purpose"] != "frozen_candidate":
        raise ReviewExecutionRejected("Candidate finalization requires frozen Candidate")
    axes = verified_first_party_semantic_review_passes(
        binding, repository=Path(session["worktree"]), root=root, signers=signers,
        root_owned_signers=root_owned_signers, now_unix=now,
    )
    record = {
        "schema_version": 1, "kind": "grabowski_first_party_candidate_handoff_v1",
        "binding": binding, "session_id": session_id, "axes": axes,
        "issuer": authenticated, "finalized_at_unix": now,
    }
    lock = _first_party_lock(root)
    try:
        _assert_first_party_source_current(session)
        _write_signed_record(
            session_root / "finalized.json", record, key=key, signers=signers,
            max_bytes=MAX_CANDIDATE_FINALIZED_RECEIPT, atomic=True,
        )
    finally:
        _release_first_party_lock(lock)
    return record


def verified_first_party_candidate_handoff(
    plan: dict[str, Any], *, root: Path = FIRST_PARTY_REVIEW_ROOT,
    signers: Path = TRUSTED_SIGNERS, root_owned_signers: bool = True,
    now_unix: int | None = None,
) -> dict[str, Any]:
    binding, repository, _raw = _assert_plan_source(plan)
    if binding["review_purpose"] != "frozen_candidate":
        raise ReviewExecutionRejected("frozen Candidate handoff required")
    axes = verified_first_party_semantic_review_passes(
        binding, repository=repository, root=root, signers=signers,
        root_owned_signers=root_owned_signers, now_unix=now_unix,
    )
    session_id = next(iter(axes.values()))["provenance"]["session_id"]
    record = _read_signed_record(
        root / "sessions" / session_id / "finalized.json", signers=signers,
        root_owned_signers=root_owned_signers,
        max_bytes=MAX_CANDIDATE_FINALIZED_RECEIPT,
    )
    session = _read_signed_record(
        root / "sessions" / session_id / "session.json", signers=signers,
        root_owned_signers=root_owned_signers,
    )
    if (
        set(record) != {"schema_version", "kind", "binding", "session_id", "axes", "issuer", "finalized_at_unix"}
        or record.get("schema_version") != 1
        or record.get("kind") != "grabowski_first_party_candidate_handoff_v1"
        or record.get("binding") != binding or record.get("session_id") != session_id
        or record.get("axes") != axes
        or type(record.get("finalized_at_unix")) is not int
        or not session["created_at_unix"] <= record["finalized_at_unix"] <= session["expires_at_unix"]
    ):
        raise ReviewExecutionRejected("Candidate signed handoff mismatch")
    _issuer_matches_session(record["issuer"], session, expected_tool=FIRST_PARTY_TOOL_SUBMIT)
    _assert_first_party_source_current(session)
    return {"verdict": "PASS", "findings": []}



def _assert_prior_first_party_material_findings_resolved(
    session: dict[str, Any], current_axes: dict[str, dict[str, Any]], *,
    root: Path, repository: Path, signers: Path, root_owned_signers: bool,
) -> None:
    """An unchanged revision cannot discard a signed REJECT by rotating batches.

    A later signed review of the same axis must explicitly resolve each old
    finding by ID and severity, with source-attested evidence and a newer
    submission. Other revisions remain independent. All historical signed
    axes are read, including partial sessions whose REJECT was submitted.
    """
    sessions = root / "sessions"
    # Keep only signed finding identities/timestamps, not entire old reports.
    # This preserves unbounded registry iteration without a second archive.
    legacy_history_only = "canonical_diff_sha256" not in session
    unresolved_latest: dict[tuple[str, str, str], int] = {}
    resolved_latest: dict[tuple[str, str, str], int] = {}
    lock = _first_party_lock(root, read_only=True)
    try:
        decisive = session["binding"]
        fd = _private_dir(sessions)
        try:
            # Stream the registry under the shared lock. Every session signature
            # is verified before revision filtering, without a global size cap.
            with os.scandir(fd) as entries:
                for entry in entries:
                    name = entry.name
                    if ID.fullmatch(name) is None:
                        raise ReviewExecutionRejected("first-party session registry name invalid")
                    if name == session["session_id"]:
                        continue
                    historical_root = sessions / name
                    old = _read_signed_record(
                        historical_root / "session.json", signers=signers,
                        root_owned_signers=root_owned_signers,
                    )
                    if old.get("session_id") != name or old.get("kind") != FIRST_PARTY_SESSION_KIND:
                        raise ReviewExecutionRejected("previous signed session identity invalid")
                    candidate = old.get("binding")
                    if not isinstance(candidate, dict):
                        raise ReviewExecutionRejected("previous signed session binding absent")
                    # Equivalent GitHub diff encodings cannot erase signed
                    # REJECT debt. Exact raw and canonical source digests are
                    # independently verified below before admitting history.
                    revision_fields = (
                        "repo", "pr", "base_sha", "head_sha",
                        "review_purpose", "release_binding",
                    )
                    if not all(candidate.get(k) == decisive.get(k) for k in revision_fields):
                        continue
                    if decisive.get("review_purpose") == "frozen_candidate":
                        # A new signed Test receipt changes the full Candidate
                        # binding but NOT its immutable Writer patch identity.
                        # Compare source identity, never ephemeral Test receipts,
                        # so batch rotation cannot erase a signed REJECT.
                        previous_candidate = candidate.get("candidate_binding")
                        current_candidate = decisive.get("candidate_binding")
                        if (
                            not isinstance(previous_candidate, dict)
                            or not isinstance(current_candidate, dict)
                            or candidate.get("diff_sha256") != decisive.get("diff_sha256")
                            or previous_candidate.get("candidate") != current_candidate.get("candidate")
                            or previous_candidate.get("patch_bytes_sha256")
                            != current_candidate.get("patch_bytes_sha256")
                        ):
                            continue
                    # A legacy/independent review may be dispatched from main.
                    # Verify sources against the original SIGNED review worktree,
                    # never assume that Captain\'s main checkout is the PR head.
                    historical_repository = (
                        Path(old.get("worktree")) if legacy_history_only else repository
                    )
                    if legacy_history_only and not isinstance(old.get("worktree"), str):
                        raise ReviewExecutionRejected("previous signed review worktree invalid")
                    if "canonical_diff_sha256" not in session:
                        # The legacy fallback has no current first-party batch.
                        # Inspect the signed registry first: unrelated history
                        # must not require the target revision to be checked out.
                        from grabowski_self_review_producer import _current_source

                        session["source_raw_diff_sha256"] = _current_source(
                            historical_repository, decisive,
                        )
                        session["canonical_diff_sha256"] = hashlib.sha256(
                            _first_party_diff(historical_repository, decisive)
                        ).hexdigest()
                        session["changed_paths"] = _first_party_changed_paths(
                            historical_repository, decisive,
                        )
                    old_binding = _first_party_binding(candidate)
                    if (
                        old.get("schema_version") != 1
                        or old.get("binding_sha256") != _digest(old_binding)
                        or old.get("canonical_diff_sha256") != session["canonical_diff_sha256"]
                        or old.get("source_raw_diff_sha256") != (
                            _digest(old_binding["candidate_binding"])
                            if old_binding["review_purpose"] == "frozen_candidate"
                            else session["source_raw_diff_sha256"]
                        )
                        or old.get("changed_paths") != session["changed_paths"]
                        or old.get("issuer_principal") != _first_party_principal(
                            _validate_first_party_issuer(
                                old.get("start_issuer"), expected_tool=FIRST_PARTY_TOOL_START,
                            )
                        )
                    ):
                        raise ReviewExecutionRejected("previous same-revision session origin invalid")
                    old_reads = _load_first_party_reads(
                        old, historical_root, signers=signers,
                        root_owned_signers=root_owned_signers, repository=historical_repository,
                    )
                    old_axes = _load_first_party_axes(
                        old, historical_root, reads=old_reads, signers=signers,
                        root_owned_signers=root_owned_signers,
                    )
                    for axis, old_axis in old_axes.items():
                        submitted = old_axis["submitted_at_unix"]
                        for finding in old_axis["report"]["findings"]:
                            identity = (axis, finding["id"], finding["severity"])
                            if (old_axis["report"]["verdict"] == "REJECT"
                                    and finding["verdict"] == "UNRESOLVED"):
                                unresolved_latest[identity] = max(
                                    submitted, unresolved_latest.get(identity, -1),
                                )
                            elif finding["verdict"] == "RESOLVED":
                                resolved_latest[identity] = max(
                                    submitted, resolved_latest.get(identity, -1),
                                )
            # Every historical session has now been signature/source verified.
            # A later independently signed resolution may clear earlier debt;
            # an earlier resolution cannot cancel a newly signed REJECT.
            for identity, rejected_at in unresolved_latest.items():
                axis, finding_id, severity = identity
                current = current_axes.get(axis)
                current_resolves = (
                    current is not None
                    and current["submitted_at_unix"] >= rejected_at
                    and any(
                        observed["id"] == finding_id
                        and observed["severity"] == severity
                        and observed["verdict"] == "RESOLVED"
                        for observed in current["report"]["findings"]
                    )
                )
                if not current_resolves and resolved_latest.get(identity, -1) <= rejected_at:
                    raise ReviewExecutionRejected(
                        "previous signed material finding unresolved for same revision"
                    )
        finally:
            os.close(fd)
    finally:
        _release_first_party_lock(lock)


def _assert_no_first_party_reject_for_legacy_review(
    binding: dict[str, Any], *, repository: Path, root: Path,
    signers: Path, root_owned_signers: bool,
) -> None:
    """V2-origin reviews may not sidestep an old signed first-party REJECT."""
    if not (root / "sessions").exists():
        return
    context = {
        "session_id": "",  # No current first-party batch to exempt.
        "binding": _first_party_binding(binding),
    }
    _assert_prior_first_party_material_findings_resolved(
        context, {}, root=root, repository=repository, signers=signers,
        root_owned_signers=root_owned_signers,
    )

def submit_first_party_axis_review(
    session_id: str, nonce: str, report: dict[str, Any],
    issuer: dict[str, Any], *,
    root: Path = FIRST_PARTY_REVIEW_ROOT,
    key: Path = SIGNING_KEY,
    signers: Path = TRUSTED_SIGNERS,
    root_owned_signers: bool = True,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Persist one immutable model/human-written axis report after real reads."""
    observed_at = int(time.time()) if now_unix is None else now_unix
    session, session_root = _load_first_party_session(
        session_id, nonce, root=root, signers=signers,
        root_owned_signers=root_owned_signers, now_unix=observed_at,
        require_fresh=True,
    )
    authenticated = _issuer_matches_session(
        issuer, session, expected_tool=FIRST_PARTY_TOOL_SUBMIT,
    )
    signers = _allowed_signers(signers, root_owned=root_owned_signers)
    lock = _first_party_lock(root)
    try:
        worktree = _assert_first_party_source_current(session)
        reads = _load_first_party_reads(
            session, session_root, signers=signers,
            root_owned_signers=root_owned_signers, repository=worktree,
        )
        existing = _load_first_party_axes(
            session, session_root, reads=reads, signers=signers,
            root_owned_signers=root_owned_signers,
        )
        axis = report.get("axis") if isinstance(report, dict) else None
        if axis not in REQUIRED_AXES:
            raise ReviewExecutionRejected("first-party submitted axis invalid")
        if axis in existing:
            raise ReviewExecutionRejected("first-party axis review duplicated")
        prior_observations = {
            observation
            for item in existing.values()
            for observation in item["report"]["axis_observations"]
        }
        normalized = _validate_first_party_report(
            report, axis=axis, reads=reads, binding=session["binding"],
            prior_observations=prior_observations,
        )
        record = {
            "schema_version": 1, "kind": FIRST_PARTY_AXIS_KIND,
            "session_id": session_id, "binding_sha256": session["binding_sha256"],
            "axis": axis, "report": normalized, "report_sha256": _digest(normalized),
            "issuer": authenticated, "submitted_at_unix": observed_at,
        }
        axis_path = session_root / "axes" / (axis + ".json")
        if axis_path.exists():
            raise ReviewExecutionRejected("first-party axis review duplicated")
        receipt_sha256, _signature_sha256 = _write_signed_record(
            axis_path, record, key=key, signers=signers,
            atomic=True,
        )
    finally:
        _release_first_party_lock(lock)
    completed = len(existing) + 1
    return {
        "status": "axis_rejected" if normalized["verdict"] == "REJECT" else "axis_accepted",
        "review_session_id": session_id, "axis": axis,
        "axis_receipt_sha256": receipt_sha256,
        "accepted_axis_count": completed,
        "session_complete": completed == len(REQUIRED_AXES),
        "material_findings": sum(
            item["verdict"] == "UNRESOLVED" for item in normalized["findings"]
        ),
        "does_not_establish": ["technical_task_pass", "Captain_merge", "deployment"],
    }


def verified_first_party_semantic_review_passes(
    binding: dict[str, Any], *, repository: Path | None,
    root: Path = FIRST_PARTY_REVIEW_ROOT,
    signers: Path = TRUSTED_SIGNERS,
    root_owned_signers: bool = True,
    now_unix: int | None = None,
    axes_to_review: tuple[str, ...] = REQUIRED_AXES,
) -> dict[str, dict[str, Any]]:
    """Verify five signed controller reports and every persisted source read."""
    expected = _first_party_binding(binding)
    if axes_to_review != REQUIRED_AXES:
        raise ReviewExecutionRejected("first-party semantic method scope invalid")
    index_path = root / "batches" / (expected["review_batch_id"] + ".json")
    try:
        parent_fd = _private_dir(index_path.parent)
        try:
            index = _json_record(_private_read(parent_fd, index_path.name, limit=4096))
        finally:
            os.close(parent_fd)
    except FileNotFoundError as exc:
        raise FirstPartyReviewAbsent("first-party semantic review session absent") from exc
    if (
        set(index) != {
            "schema_version", "kind", "review_batch_id", "session_id",
            "binding_sha256", "session_receipt_sha256", "session_signature_sha256",
        }
        or index.get("schema_version") != 1
        or index.get("kind") != "grabowski_first_party_review_batch_index_v1"
        or index.get("review_batch_id") != expected["review_batch_id"]
        or index.get("binding_sha256") != _digest(expected)
        or not isinstance(index.get("session_id"), str)
        or ID.fullmatch(index["session_id"]) is None
        or not isinstance(index.get("session_receipt_sha256"), str)
        or SHA256.fullmatch(index["session_receipt_sha256"]) is None
        or not isinstance(index.get("session_signature_sha256"), str)
        or SHA256.fullmatch(index["session_signature_sha256"]) is None
    ):
        raise ReviewExecutionRejected("first-party batch index invalid")
    session_id = index["session_id"]
    session_path = root / "sessions" / session_id / "session.json"
    session = _read_signed_record(
        session_path, signers=signers, root_owned_signers=root_owned_signers,
    )
    start_issuer = _validate_first_party_issuer(
        session.get("start_issuer"), expected_tool=FIRST_PARTY_TOOL_START,
    )
    if (
        set(session) != {
            "schema_version", "kind", "session_id", "session_nonce_sha256",
            "binding", "binding_sha256", "worktree", "source_raw_diff_sha256",
            "canonical_diff_sha256", "changed_paths", "issuer_principal",
            "start_issuer", "created_at_unix", "expires_at_unix",
        }
        or session.get("schema_version") != 1
        or session.get("kind") != FIRST_PARTY_SESSION_KIND
        or session.get("binding") != expected
        or session.get("binding_sha256") != _digest(expected)
        or session.get("session_id") != session_id
        or not isinstance(session.get("session_nonce_sha256"), str)
        or SHA256.fullmatch(session["session_nonce_sha256"]) is None
        or not isinstance(session.get("source_raw_diff_sha256"), str)
        or SHA256.fullmatch(session["source_raw_diff_sha256"]) is None
        or not isinstance(session.get("canonical_diff_sha256"), str)
        or SHA256.fullmatch(session["canonical_diff_sha256"]) is None
        or not isinstance(session.get("worktree"), str)
        or not session["worktree"].startswith("/")
        or ".." in Path(session["worktree"]).parts
        or session.get("issuer_principal") != _first_party_principal(start_issuer)
        or type(session.get("created_at_unix")) is not int
        or type(session.get("expires_at_unix")) is not int
        or session["expires_at_unix"] - session["created_at_unix"]
        != FIRST_PARTY_SESSION_TTL_SECONDS
    ):
        raise ReviewExecutionRejected("first-party session crossed review binding")
    from grabowski_self_review_producer import (
        _current_source, _managed_repository_identity,
    )
    session_repository, _session_slug = _managed_repository_identity(
        Path(session["worktree"]), expected_repo=expected["repo"],
    )
    if repository is not None:
        supplied_repository, _supplied_slug = _managed_repository_identity(
            repository, expected_repo=expected["repo"],
        )
        if supplied_repository != session_repository:
            raise ReviewExecutionRejected("first-party repository crossed review session")
    repository = session_repository
    if _current_source(repository, expected) != session["source_raw_diff_sha256"]:
        raise ReviewExecutionRejected("first-party verified source identity changed")
    material = _canonical(session)
    parent_fd = _private_dir(session_path.parent)
    try:
        signature = _private_read(parent_fd, "session.sig", limit=16384)
    finally:
        os.close(parent_fd)
    if (
        hashlib.sha256(material).hexdigest() != index["session_receipt_sha256"]
        or hashlib.sha256(signature).hexdigest() != index["session_signature_sha256"]
    ):
        raise ReviewExecutionRejected("first-party indexed session bytes changed")
    diff = _first_party_diff(repository, expected)
    if hashlib.sha256(diff).hexdigest() != session.get("canonical_diff_sha256"):
        raise ReviewExecutionRejected("first-party verified Git diff changed")
    observed_at = int(time.time()) if now_unix is None else now_unix
    # Session expiry prevents new source reads/submissions, not the later
    # verification of completed signed reviews. Signed timestamps of all
    # source reads and axis reports remain bounded by that original window.
    if type(observed_at) is not int or observed_at < session["created_at_unix"]:
        raise ReviewExecutionRejected("first-party review verification time invalid")
    session_root = session_path.parent
    reads = _load_first_party_reads(
        session, session_root, signers=signers,
        root_owned_signers=root_owned_signers, repository=repository,
    )
    # No review PASS from a single authentic but incomplete diff excerpt.
    # Every line of the immutable base/head delta must have been returned to
    # the enrolled controller across the signed source-read receipts.
    try:
        diff_line_count = len(diff.decode("utf-8").splitlines(keepends=True))
    except UnicodeError as exc:
        raise ReviewExecutionRejected("first-party canonical diff not text") from exc
    next_unseen = 1
    ranges = sorted(
        (item["start_line"], item["end_line"])
        for item in reads if item["read_kind"] == "diff"
    )
    for first, last in ranges:
        if first > next_unseen:
            break
        next_unseen = max(next_unseen, last + 1)
        if next_unseen > diff_line_count:
            break
    if next_unseen <= diff_line_count:
        raise ReviewExecutionRejected("first-party canonical diff coverage incomplete")
    axes = _load_first_party_axes(
        session, session_root, reads=reads, signers=signers,
        root_owned_signers=root_owned_signers,
    )
    if set(axes) != set(axes_to_review):
        raise ReviewExecutionRejected("first-party semantic axis coverage incomplete")
    _assert_prior_first_party_material_findings_resolved(
        session, axes, root=root, repository=repository,
        signers=signers, root_owned_signers=root_owned_signers,
    )
    accepted: dict[str, dict[str, Any]] = {}
    for sequence, axis in enumerate(axes_to_review, start=1):
        record = axes[axis]
        report = record["report"]
        if (
            report["verdict"] != "PASS"
            or any(item["verdict"] == "MATERIAL" for item in report["reviewed_risks"])
            or any(item["verdict"] == "UNRESOLVED" for item in report["findings"])
        ):
            raise ReviewExecutionRejected("first-party semantic material finding unresolved")
        phase = {
            "n": sequence, "axis": axis, "summary": report["summary"],
            "evidence_refs": report["evidence_refs"], "material_findings": 0,
        }
        accepted[axis] = {
            "phase": phase,
            "provenance_kind": "first_party_authenticated_controller",
            "provenance": {
                "session_id": session_id,
                "session_receipt_sha256": index["session_receipt_sha256"],
                "issuer_principal_sha256": _digest(session["issuer_principal"]),
                "axis_receipt_sha256": hashlib.sha256(_canonical(record)).hexdigest(),
                "axis_report_sha256": record["report_sha256"],
                "source_reads_sha256": _digest(sorted(
                    item["data_sha256"] for item in reads if item["axis"] == axis
                )),
                "canonical_diff_sha256": session["canonical_diff_sha256"],
            },
        }
    _assert_first_party_source_current(session)
    return accepted




def _verified_provider_semantic_bytes(
    receipt: dict[str, Any], raw: bytes, *,
    provider_family: str, binding: dict[str, Any],
) -> bytes:
    """Reparse actual provider trace, never a caller-authored normalized claim.

    The model's stdout is a Claude success envelope, a Grok event stream or
    directly emitted JSON. All three are separately origin-bound by V2 role
    reconciliation; only the verified complete document enters the producer.
    """
    from grabowski_agent_role import (
        CLAUDE_REVIEW_JSON_CONTRACT,
        GROK_REVIEW_STREAM_CONTRACT,
        _extract_claude_review_document,
        _extract_grok_stream_review_document,
    )
    if provider_family == "anthropic":
        if (
            receipt.get("review_provider_contract") != CLAUDE_REVIEW_JSON_CONTRACT
            or receipt.get("review_provider_stream_contract") is not None
        ):
            raise ReviewExecutionRejected("semantic V2 Claude provider contract missing")
        document, error, metadata = _extract_claude_review_document(raw)
    elif provider_family == "xai":
        if (
            receipt.get("review_provider_stream_contract") != GROK_REVIEW_STREAM_CONTRACT
            or receipt.get("review_provider_contract") is not None
        ):
            raise ReviewExecutionRejected("semantic V2 Grok provider contract missing")
        document, error, metadata = _extract_grok_stream_review_document(
            raw, expected_head=binding["head_sha"],
            expected_base_head=binding["base_sha"],
        )
    else:
        if (
            receipt.get("review_provider_contract") is not None
            or receipt.get("review_provider_stream_contract") is not None
        ):
            raise ReviewExecutionRejected("semantic V2 provider contract mismatched")
        # Other cataloged V2 reviewer roles emit direct JSON. Their frozen
        # command, output SHA, read-only sandbox and origin remain mandatory.
        return raw
    if error is not None or document is None:
        raise ReviewExecutionRejected("semantic V2 provider output not authentic")
    if any(receipt.get(k) != v for k, v in metadata.items()):
        raise ReviewExecutionRejected("semantic V2 provider metadata altered")
    if (
        receipt.get("review_document_bytes") != len(document)
        or receipt.get("review_document_sha256") != hashlib.sha256(document).hexdigest()
        or receipt.get("review_document_normalizations") != []
        or receipt.get("review_findings_normalized") is not False
    ):
        raise ReviewExecutionRejected("semantic V2 provider review document digest drift")
    return document


def _unique_semantic_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Never let duplicate JSON keys hide REJECTs or wrong revision bindings."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ReviewExecutionRejected("duplicate semantic V2 JSON field")
        result[name] = value
    return result


def _verified_v2_semantic_review_passes(
    binding: dict[str, Any], *, repository: Path,
    axes_to_review: tuple[str, ...] = REQUIRED_AXES,
) -> dict[str, dict[str, Any]]:
    """Use existing V2 role origins, never green test tasks, as semantic authority.

    The reviewer role must have actually executed a catalog-bound, read-only
    model route on the exact revision.  Its full structured JSON analysis must
    survive unchanged inside the recorded, digest-bound role stdout. Missing,
    abbreviated, provider-failed or fabricated reviews are a hard BLOCK.
    """
    import grabowski_decision_reviews as decisions

    expected = {
        key: binding[key] for key in (
            "repo", "pr", "base_sha", "head_sha", "diff_sha256",
            "review_batch_id", "review_purpose",
        )
    }
    result = decisions.reconcile(
        repo=expected["repo"], pr=expected["pr"],
        head_sha=expected["head_sha"], base_sha=expected["base_sha"],
        diff_sha256=expected["diff_sha256"],
    )
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("attempts"), list)
        or not isinstance(result.get("errors"), list)
    ):
        raise ReviewExecutionRejected("substantive V2 reviewer execution not settled")
    # The V2 registry also contains unrelated optional decision-bound reviews.
    # Captain already distinguishes authenticated *pre-result* infrastructure
    # absence from a semantic result. Apply that SAME exact classifier, rather
    # than making five valid self-review role receipts depend on an optional
    # provider's quota. Never ignore an ambiguous result, a REJECT, a running
    # reviewer, malformed evidence, or failures of the mandatory selfrev slots.
    if result.get("status") == "settled" and result["errors"] == []:
        pass
    elif result.get("status") == "blocked" and result["errors"]:
        from grabowski_merge_guard import decision_review_blocking_errors
        optional = decision_review_blocking_errors(
            result, independent_required=False,
        )
        if optional["status"] != "optional_unavailable" or optional["errors"]:
            raise ReviewExecutionRejected("substantive V2 reviewer execution not settled")
    else:
        raise ReviewExecutionRejected("substantive V2 reviewer execution not settled")
    attempts = result["attempts"]
    if not (
        axes_to_review == REQUIRED_AXES
        or axes_to_review == (*REQUIRED_AXES, "additional_adversarial_probe")
    ):
        raise ReviewExecutionRejected("semantic method scope invalid")
    accepted: dict[str, dict[str, Any]] = {}
    used_units: set[str] = set()
    summaries: set[str] = set()
    for sequence, axis in enumerate(axes_to_review, start=1):
        slot = f"selfrev.{expected['review_batch_id'][:16]}.{axis}"
        matches = [item for item in attempts if item.get("slot") == slot]
        passes = [item for item in matches if item.get("classification") == "pass"]
        if len(passes) != 1:
            raise ReviewExecutionRejected("substantive V2 reviewer axis absent or ambiguous")
        item = passes[0]
        if any(
            prior is not item
            and (
                prior.get("classification") != "infrastructure_error"
                or prior.get("terminal") is not True
                or not decisions._attempt_started_after(item, prior)
            )
            for prior in matches
        ):
            raise ReviewExecutionRejected("substantive V2 reviewer axis absent or ambiguous")
        if (
            item.get("classification") != "pass"
            or item.get("terminal") is not True
            or item.get("terminal_status") != "succeeded"
            # Self-review authenticity is established by the independently
            # reconciled, server-bound read-only role AND verified route.
            # independence_verified is an *additional* optional external
            # reviewer-admission predicate, not a five-phase review gate.
            # Captain separately enforces an explicitly opted-in independent
            # review and retains every real material REJECT.
            or item.get("review_role_verified") is not True
            or item.get("review_route_verified") is not True
            or item.get("verdict") != "PASS_THIS_REVISION"
            or item.get("material_findings") != 0
            or any(
                not isinstance(item.get(key), str)
                or not item[key]
                for key in (
                    "origin_sha256", "result_sha256",
                    "review_role_receipt_sha256",
                    "review_route_id", "review_provider_family",
                )
            )
        ):
            raise ReviewExecutionRejected("substantive V2 reviewer result not authenticated")
        unit = item.get("unit")
        if (
            not isinstance(unit, str)
            or re.fullmatch(r"grabowski-job-[0-9a-f]{12}", unit) is None
            or unit in used_units
        ):
            raise ReviewExecutionRejected("substantive V2 reviewer task replayed")
        used_units.add(unit)
        path = decisions.JOBS_ROOT / unit / decisions.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
        try:
            receipt = decisions._read_private_json(
                path, decisions.MAX_ROLE_RECEIPT_BYTES,
                require_private_parent=True,
            )
        except (OSError, ValueError) as exc:
            raise ReviewExecutionRejected("substantive V2 role receipt unavailable") from exc
        if (
            receipt.get("receipt_sha256") != item["review_role_receipt_sha256"]
            or receipt.get("receipt_sha256") != decisions._agent_role_receipt_sha256(receipt)
            or receipt.get("verdict") != "PASS"
            or receipt.get("findings") != []
            or receipt.get("failure_classification") != "passed"
            or receipt.get("returncode") != 0
        ):
            raise ReviewExecutionRejected("substantive V2 role receipt drifted")
        stdout_tail = receipt.get("stdout_tail")
        if not isinstance(stdout_tail, str) or len(stdout_tail) > 262144:
            raise ReviewExecutionRejected("substantive V2 review content missing")
        full = stdout_tail.encode("utf-8")
        if (
            receipt.get("stdout_bytes") != len(full)
            or receipt.get("stdout_sha256") != hashlib.sha256(full).hexdigest()
        ):
            raise ReviewExecutionRejected("substantive V2 review output truncated")
        observed = _verified_provider_semantic_bytes(
            receipt, full,
            provider_family=item["review_provider_family"],
            binding=expected,
        )
        try:
            document = json.loads(
                observed.decode("utf-8"),
                object_pairs_hook=_unique_semantic_json_object,
            )
        except (ValueError, UnicodeError) as exc:
            raise ReviewExecutionRejected("substantive V2 review document invalid") from exc
        if receipt.get("review_document_object_sha256") != decisions._agent_role_command_sha256(document):
            raise ReviewExecutionRejected("substantive V2 document digest invalid")
        fields = {
            "schema_version", "kind", "repo", "pr",
            "base_sha", "head_sha", "diff_sha256",
            "review_batch_id", "review_purpose", "axis", "verdict",
            "findings", "summary", "evidence_refs", "reviewed_risks",
        }
        if expected["review_purpose"] == "post_merge_release":
            fields.add("release_binding")
        if (
            not isinstance(document, dict)
            or set(document) != fields
            or document.get("schema_version") != 1
            or document.get("kind") != "grabowski_semantic_self_review_v1"
            or document.get("verdict") != "PASS"
            or document.get("findings") != []
            or document.get("axis") != axis
            or any(document.get(key) != value for key, value in expected.items())
            or (
                expected["review_purpose"] == "post_merge_release"
                and document.get("release_binding") != binding.get("release_binding")
            )
        ):
            raise ReviewExecutionRejected("substantive V2 review binding or findings invalid")
        summary = document["summary"]
        references = document["evidence_refs"]
        risks = document["reviewed_risks"]
        if (
            not isinstance(summary, str) or len(" ".join(summary.split())) < 160
            or summary in summaries
            or not isinstance(references, list)
            or not 1 <= len(references) <= MAX_REFERENCES
            or not isinstance(risks, list)
            or not 2 <= len(risks) <= 16
        ):
            raise ReviewExecutionRejected("substantive V2 review lacks analysis")
        summaries.add(summary)
        for reference in references:
            _source_reference(
                reference, head=expected["head_sha"], base=expected["base_sha"],
                repository=repository, read_source=None,
            )
        named_risks: set[str] = set()
        for risk in risks:
            if (
                not isinstance(risk, dict)
                or set(risk) != {"risk", "assessment", "evidence_refs"}
                or not isinstance(risk["risk"], str) or len(risk["risk"].strip()) < 15
                or risk["risk"] in named_risks
                or not isinstance(risk["assessment"], str)
                or len(" ".join(risk["assessment"].split())) < 80
                or not isinstance(risk["evidence_refs"], list)
                or not 1 <= len(risk["evidence_refs"]) <= MAX_REFERENCES
            ):
                raise ReviewExecutionRejected("substantive V2 review risk analysis inadequate")
            named_risks.add(risk["risk"])
            for reference in risk["evidence_refs"]:
                _source_reference(
                    reference, head=expected["head_sha"], base=expected["base_sha"],
                    repository=repository, read_source=None,
                )
        phase = {
            "n": sequence, "axis": axis, "summary": summary,
            "evidence_refs": references, "material_findings": 0,
        }
        accepted[axis] = {
            "phase": phase,
            "provenance": {
                "slot": slot,
                "unit": unit,
                "origin_sha256": item["origin_sha256"],
                "result_sha256": item["result_sha256"],
                "review_role_receipt_sha256": item["review_role_receipt_sha256"],
                "review_route_id": item["review_route_id"],
                "review_provider_family": item["review_provider_family"],
                "semantic_document_sha256": hashlib.sha256(full).hexdigest(),
                "reviewed_risks_sha256": _digest(risks),
            },
        }
    return accepted


def verified_semantic_review_passes(
    binding: dict[str, Any], *, repository: Path,
    axes_to_review: tuple[str, ...] = REQUIRED_AXES,
) -> dict[str, dict[str, Any]]:
    """Use signed first-party model tool interactions, or genuine V2 role results."""
    try:
        return verified_first_party_semantic_review_passes(
            binding, repository=repository, axes_to_review=axes_to_review,
        )
    except FirstPartyReviewAbsent:
        return _verified_v2_semantic_review_passes(
            binding, repository=repository, axes_to_review=axes_to_review,
        )


def _verify(
    audit: dict[str, Any],
    *,
    receipts: Path,
    outcomes: Path,
    signers: Path,
    repository: Path | None,
    now_unix: int,
    root_owned_signers: bool,
    read_source: Callable[[str, str], bytes] | None = None,
    capture_root: Path = CAPTURE_ROOT,
    first_party_root: Path = FIRST_PARTY_REVIEW_ROOT,
) -> None:
    if not isinstance(audit, dict):
        raise ReviewExecutionRejected("self-review audit is absent")
    repo, pr = audit.get("repo"), audit.get("pr")
    base, head, diff = (
        audit.get("base_sha"), audit.get("head_sha"), audit.get("diff_sha256")
    )
    batch = audit.get("review_batch_id")
    if (
        not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
        or type(pr) is not int or pr <= 0
        or not isinstance(base, str) or not SHA40.fullmatch(base)
        or not isinstance(head, str) or not SHA40.fullmatch(head)
        or not isinstance(diff, str) or not SHA256.fullmatch(diff)
        or not isinstance(batch, str) or not ID.fullmatch(batch)
    ):
        raise ReviewExecutionRejected("self-review phase/revision binding invalid")
    purpose = audit.get("review_purpose", "pull_request")
    if purpose not in {"pull_request", "post_merge_release"}:
        raise ReviewExecutionRejected("self-review purpose invalid")
    release_binding = audit.get("release_binding")
    if purpose == "post_merge_release":
        if (
            not isinstance(release_binding, dict)
            or set(release_binding) != {
                "serving_release_id", "serving_tree", "target_tree",
            }
            or not isinstance(release_binding["serving_release_id"], str)
            or not release_binding["serving_release_id"]
            or any(
                not isinstance(release_binding[key], str)
                or not SHA40.fullmatch(release_binding[key])
                for key in ("serving_tree", "target_tree")
            )
        ):
            raise ReviewExecutionRejected("release source/tree binding invalid")
    elif release_binding is not None:
        raise ReviewExecutionRejected("PR self-review contains release-only binding")
    phases = audit.get("review_iterations")
    refs = audit.get("review_pass_receipts")
    if (
        not isinstance(phases, list) or not 5 <= len(phases) <= 32
        or not isinstance(refs, list) or len(refs) != len(phases)
    ):
        raise ReviewExecutionRejected("self-review receipt coverage incomplete")
    axes = [item.get("axis") if isinstance(item, dict) else None for item in phases]
    if (
        axes[:5] != list(REQUIRED_AXES)
        or any(not isinstance(axis, str) for axis in axes)
        or len(axes) != len(set(axes))
    ):
        raise ReviewExecutionRejected("self-review method axes invalid or duplicated")
    semantic_binding = {
        "repo": repo, "pr": pr, "base_sha": base, "head_sha": head,
        "diff_sha256": diff, "review_batch_id": batch,
        "review_purpose": purpose,
        **({"release_binding": release_binding} if purpose == "post_merge_release" else {}),
    }
    review_origin = audit.get("review_origin")
    if review_origin is not None and review_origin != FIRST_PARTY_AUDIT_ORIGIN:
        raise ReviewExecutionRejected("self-review origin invalid")
    if review_origin == FIRST_PARTY_AUDIT_ORIGIN:
        semantic_reviews = verified_first_party_semantic_review_passes(
            semantic_binding, repository=repository, root=first_party_root,
            signers=signers, root_owned_signers=root_owned_signers,
            now_unix=now_unix, axes_to_review=tuple(axes),
        )
        for phase, ref in zip(phases, refs, strict=True):
            axis = phase.get("axis") if isinstance(phase, dict) else None
            semantic = semantic_reviews.get(axis)
            if (
                not isinstance(semantic, dict)
                or semantic.get("provenance_kind")
                != "first_party_authenticated_controller"
                or phase != semantic.get("phase")
            ):
                raise ReviewExecutionRejected(
                    "direct first-party audit phase differs from signed axis output"
                )
            expected_ref = {
                "kind": FIRST_PARTY_AUDIT_ORIGIN,
                "axis": axis,
                "repo": repo,
                "base_sha": base,
                "head_sha": head,
                "diff_sha256": diff,
                "binding_sha256": _digest(semantic_binding),
                **semantic["provenance"],
            }
            if ref != expected_ref:
                raise ReviewExecutionRejected(
                    "direct first-party audit proof differs from signed records"
                )
        return
    if repository is None:
        raise ReviewExecutionRejected("legacy self-review repository absent")
    _assert_no_first_party_reject_for_legacy_review(
        semantic_binding, repository=repository, root=first_party_root,
        signers=signers, root_owned_signers=root_owned_signers,
    )
    semantic_reviews = verified_semantic_review_passes(
        semantic_binding, repository=repository, axes_to_review=tuple(axes),
    )
    signer = _allowed_signers(signers, root_owned=root_owned_signers)
    root_fd = _private_dir(receipts)
    seen_ids: set[str] = set()
    seen_tasks: set[str] = set()
    seen_nonces: set[str] = set()
    try:
        for index, (phase, ref) in enumerate(zip(phases, refs, strict=True), start=1):
            if not isinstance(phase, dict) or not isinstance(ref, dict) or set(ref) != {
                "id", "receipt_sha256", "signature_sha256", "output_sha256",
            }:
                raise ReviewExecutionRejected("self-review phase receipt reference malformed")
            identity = ref["id"]
            if not isinstance(identity, str) or not ID.fullmatch(identity) or identity in seen_ids:
                raise ReviewExecutionRejected("self-review receipt identity replayed")
            seen_ids.add(identity)
            for name in ("receipt_sha256", "signature_sha256", "output_sha256"):
                value = ref.get(name)
                if not isinstance(value, str) or not SHA256.fullmatch(value):
                    raise ReviewExecutionRejected("self-review receipt digest malformed")
            material = _private_read(root_fd, identity + ".json", limit=MAX_RECEIPT)
            signature = _private_read(root_fd, identity + ".sig", limit=16384)
            output = _private_read(root_fd, identity + ".out", limit=MAX_OUTPUT)
            if (
                hashlib.sha256(material).hexdigest() != ref["receipt_sha256"]
                or hashlib.sha256(signature).hexdigest() != ref["signature_sha256"]
                or hashlib.sha256(output).hexdigest() != ref["output_sha256"]
            ):
                raise ReviewExecutionRejected("self-review private receipt bytes changed")
            # A PASS must be the observed output of the allowlisted method,
            # but tampered bytes must first fail the exact private hash check.
            if re.search(rb"Ran [1-9][0-9]* tests? in ", output) is None or b"\nOK\n" not in output:
                raise ReviewExecutionRejected("self-review method execution output lacks tested PASS")
            record = _json_record(material)
            _check_signature(material, signature, signer)
            expected_binding = {
                "repo": repo, "pr": pr, "base_sha": base,
                "head_sha": head, "diff_sha256": diff, "review_batch_id": batch,
                "review_purpose": purpose,
                **(
                    {"release_binding": release_binding}
                    if purpose == "post_merge_release" else {}
                ),
            }
            if record.get("binding") != expected_binding:
                raise ReviewExecutionRejected("self-review signed binding mismatch")
            expected_semantic = semantic_reviews.get(phase.get("axis"))
            semantic_kind = (
                expected_semantic.get("provenance_kind", "v2_model_role")
                if isinstance(expected_semantic, dict) else None
            )
            semantic_field = (
                "semantic_first_party"
                if semantic_kind == "first_party_authenticated_controller"
                else "semantic_v2"
            )
            if (
                not isinstance(expected_semantic, dict)
                or semantic_kind not in {
                    "v2_model_role", "first_party_authenticated_controller",
                }
                or phase != expected_semantic.get("phase")
                or record.get(semantic_field) != expected_semantic.get("provenance")
                or (
                    semantic_field == "semantic_first_party"
                    and record.get("semantic_v2") is not None
                )
                or (
                    semantic_field == "semantic_v2"
                    and record.get("semantic_first_party") is not None
                )
            ):
                raise ReviewExecutionRejected(
                    "signed self-review not based on authentic semantic review"
                )
            if (
                record.get("schema_version") != 1
                or record.get("kind") != KIND
                or record.get("producer") != PRODUCER
                or record.get("n") != index
                or record.get("axis") != phase.get("axis")
                or record.get("review_pass_sha256") != _digest(phase)
                or record.get("stdout_sha256") != ref["output_sha256"]
                or record.get("sandbox") != "isolated-read-only"
                or record.get("exit_code") != 0
            ):
                raise ReviewExecutionRejected("self-review signed phase origin mismatch")
            nonce = record.get("execution_nonce")
            task = record.get("task")
            if (
                not isinstance(nonce, str) or not ID.fullmatch(nonce)
                or nonce in seen_nonces or not isinstance(task, dict)
                or task.get("id") in seen_tasks
            ):
                raise ReviewExecutionRejected("self-review task or nonce replayed")
            seen_nonces.add(nonce)
            seen_tasks.add(task["id"])
            created = record.get("observed_at_unix")
            if (
                type(created) is not int or created > now_unix + 60
                or created < now_unix - 86400
            ):
                raise ReviewExecutionRejected("self-review execution observation stale")
            references = phase.get("evidence_refs")
            if not isinstance(references, list) or not 1 <= len(references) <= MAX_REFERENCES:
                raise ReviewExecutionRejected("self-review phase evidence references missing")
            if record.get("evidence_refs_sha256") != _digest(references):
                raise ReviewExecutionRejected("self-review evidence list was not observed by issuer")
            _task_outcome(record, outcomes, output, capture_root=capture_root)
            attested_report = observed_phase_report(
                output, binding=expected_binding, axis=phase["axis"],
            )
            if record.get("source_inspection_report_sha256") != _digest(attested_report):
                raise ReviewExecutionRejected(
                    "signed source inspection differs from recorded technical task"
                )
            for item in references:
                _source_reference(
                    item, head=head, repository=repository,
                    read_source=read_source, base=base,
                )
    finally:
        os.close(root_fd)


def review_receipt_errors(
    audit: Any, *,
    _receipts: Path = RECEIPT_ROOT,
    _signers: Path = TRUSTED_SIGNERS,
    _first_party_root: Path = FIRST_PARTY_REVIEW_ROOT,
    _repository: Path | None = None,
    _root_owned_signers: bool = True,
    _now_unix: int | None = None,
) -> list[str]:
    """Verify Captain/Gate evidence; production callers use pinned defaults.

    Underscored overrides exist only for real offline cryptographic fixtures;
    no serialized audit field can select a signer, state root, or checkout.
    """
    try:
        direct = (
            isinstance(audit, dict)
            and audit.get("review_origin") == FIRST_PARTY_AUDIT_ORIGIN
        )
        repository = _repository
        if repository is None and not direct:
            repository = Path.home() / "repos/grabowski"
        _verify(
            audit, receipts=_receipts, outcomes=OUTCOME_ROOT,
            signers=_signers, repository=repository,
            now_unix=int(time.time()) if _now_unix is None else _now_unix,
            root_owned_signers=_root_owned_signers,
            first_party_root=_first_party_root,
        )
    except (
        ReviewExecutionRejected, FileNotFoundError, PermissionError, OSError,
        TypeError, ValueError,
    ) as exc:
        return ["high_critical_server_review_provenance_invalid:" + type(exc).__name__]
    return []
