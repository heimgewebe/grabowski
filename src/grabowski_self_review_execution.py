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
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
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
MAX_OUTPUT = 1024 * 1024
MAX_SOURCE_BLOB = 2 * 1024 * 1024
MAX_REFERENCES = 64
PHASE_OBSERVATION_PREFIX = b"grabowski-phase-source-inspection-v1:"


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
        "inspection=run('diff','--name-status','-z','--no-renames',binding['base_sha'],binding['head_sha'],'--',limit=131072)\n"
        "if inspection.returncode:sys.exit(85)\n"
        "fields=inspection.stdout.split(b'\\x00')\n"
        "if len(fields)<3 or fields[-1]!=b'':sys.exit(85)\n"
        "fields=fields[:-1]\n"
        "if len(fields)%2:sys.exit(85)\n"
        "changed=[]\n"
        "for pos in range(0,len(fields),2):\n"
        "    try:status=fields[pos].decode('ascii');path=fields[pos+1].decode('utf-8')\n"
        "    except UnicodeError:sys.exit(85)\n"
        "    if status not in ('A','D','M','T') or not re.fullmatch(r'[A-Za-z0-9_.@+/-]{1,512}',path) or '..' in path.split('/'):sys.exit(87)\n"
        "    changed.append((status,path))\n"
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




def verified_semantic_review_passes(
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
        not isinstance(result, dict) or result.get("status") != "settled"
        or result.get("errors") != []
        or not isinstance(result.get("attempts"), list)
    ):
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
        if len(matches) != 1:
            raise ReviewExecutionRejected("substantive V2 reviewer axis absent or ambiguous")
        item = matches[0]
        if (
            item.get("classification") != "pass"
            or item.get("terminal") is not True
            or item.get("terminal_status") != "succeeded"
            or item.get("review_role_verified") is not True
            or item.get("review_route_verified") is not True
            or item.get("independence_verified") is not True
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
        try:
            document = json.loads(stdout_tail)
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


def _verify(
    audit: dict[str, Any],
    *,
    receipts: Path,
    outcomes: Path,
    signers: Path,
    repository: Path,
    now_unix: int,
    root_owned_signers: bool,
    read_source: Callable[[str, str], bytes] | None = None,
    capture_root: Path = CAPTURE_ROOT,
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
            if (
                not isinstance(expected_semantic, dict)
                or phase != expected_semantic.get("phase")
                or record.get("semantic_v2") != expected_semantic.get("provenance")
            ):
                raise ReviewExecutionRejected("signed self-review not based on authentic V2 semantic review")
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


def review_receipt_errors(audit: Any) -> list[str]:
    """Production gate: only server-owned trust roots, never caller paths."""
    try:
        _verify(
            audit, receipts=RECEIPT_ROOT, outcomes=OUTCOME_ROOT,
            signers=TRUSTED_SIGNERS,
            repository=Path.home() / "repos/grabowski",
            now_unix=int(time.time()), root_owned_signers=True,
        )
    except (ReviewExecutionRejected, FileNotFoundError, PermissionError, OSError) as exc:
        return ["high_critical_server_review_provenance_invalid:" + type(exc).__name__]
    return []