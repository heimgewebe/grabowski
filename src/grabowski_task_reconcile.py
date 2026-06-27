from __future__ import annotations

import argparse
import json

import grabowski_tasks


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Reconcile persistent Grabowski task records with user systemd units."
    )
    result.add_argument(
        "--auto-resume",
        action="store_true",
        help="Automatically resume only retry-safe tasks when all gates pass.",
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    result = grabowski_tasks.reconcile_tasks(auto_resume=arguments.auto_resume)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
