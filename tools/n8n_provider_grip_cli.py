#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_n8n_provider as provider


class CliError(RuntimeError):
    pass


MEMFD_RE = re.compile(r"^/proc/self/fd/[0-9]+$")
FALLBACK_SECRET_ROOT = Path.home() / ".local" / "state" / "grabowski" / "secret-use"


def _secret_bytes(path: Path) -> bytes:
    text = str(path)
    memfd = MEMFD_RE.fullmatch(text) is not None
    fallback = False
    if not memfd:
        try:
            resolved_parent = path.parent.resolve(strict=True)
        except OSError as exc:
            raise CliError("secret reference parent is unavailable") from exc
        fallback = (
            resolved_parent == FALLBACK_SECRET_ROOT.resolve(strict=False)
            and path.name.startswith("secret-")
        )
    if not memfd and not fallback:
        raise CliError("secret reference is outside the Grabowski secret-use transport")

    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise CliError("secret reference is not a regular file")
        if fallback:
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise CliError("fallback secret reference permissions are unsafe")
        data = path.read_bytes()
    except CliError:
        raise
    except Exception as exc:
        raise CliError("secret reference is not readable") from exc
    if not data:
        raise CliError("secret reference is empty")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("verify", "apply"), required=True)
    parser.add_argument("--provider-profile", required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--expected-state", choices=("isolated", "final"))
    parser.add_argument("--expected-version-id")
    parser.add_argument("--expected-response-sha256")
    return parser


def run(args: argparse.Namespace) -> dict:
    secret_data = _secret_bytes(args.secret_file)
    if args.mode == "verify":
        if args.expected_state is None:
            raise CliError("verify requires expected-state")
        if args.expected_version_id is not None or args.expected_response_sha256 is not None:
            raise CliError("verify does not accept revision preconditions")
        return provider.verify(
            provider_profile=args.provider_profile,
            secret_data=secret_data,
            expected_state=args.expected_state,
        )
    if args.expected_state is not None:
        raise CliError("apply does not accept expected-state")
    if not args.expected_version_id or not args.expected_response_sha256:
        raise CliError("apply requires expected revision and response SHA")
    return provider.apply(
        provider_profile=args.provider_profile,
        secret_data=secret_data,
        expected_version_id=args.expected_version_id,
        expected_response_sha256=args.expected_response_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CliError, provider.N8nProviderError) as exc:
        print(f"n8n provider grip failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"n8n provider grip failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)
