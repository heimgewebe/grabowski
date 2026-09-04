#!/usr/bin/env python3
"""Deterministic, read-only architecture coupling baseline for Grabowski."""

from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = 1
DOMAIN_PREFIXES = {
    "audit": ("grabowski_audit", "grabowski_chronik"),
    "blockade": ("grabowski_blockade", "grabowski_blockades"),
    "browser": ("grabowski_browser",),
    "bureau": ("grabowski_bureau",),
    "checkout": ("grabowski_checkout", "grabowski_checkouts", "grabowski_worktree"),
    "deployment": ("grabowski_deploy", "grabowski_deployment", "grabowski_self_deploy", "grabowski_recovery", "grabowski_provenance_recovery"),
    "effect": ("grabowski_effect",),
    "execution": ("grabowski_agent", "grabowski_candidate", "grabowski_execution", "grabowski_lane", "grabowski_work_acquire", "grabowski_work_admission"),
    "lifecycle": ("grabowski_lifecycle", "grabowski_terminal_convergence"),
    "operator": ("grabowski_operator", "grabowski_grips", "grabowski_operations"),
    "privileged": ("grabowski_privileged",),
    "repo_context": ("grabowski_repobrief", "grabowski_repoground"),
    "resource": ("grabowski_resource", "grabowski_resources", "grabowski_nonconflict"),
    "runtime": ("grabowski_runtime", "grabowski_serving_process"),
    "task": ("grabowski_task", "grabowski_tasks", "grabowski_workers", "grabowski_worker"),
    "transport": ("grabowski_transport", "grabowski_connector", "grabowski_client_snapshot", "grabowski_mcp"),
}


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def module_name(path: Path) -> str:
    return path.stem if path.name != "__init__.py" else path.parent.name


def source_files(repo: Path) -> list[Path]:
    return sorted(
        path
        for path in (repo / "src").glob("*.py")
        if path.is_file() and (path.name.startswith("grabowski_") or path.name == "grabowski.py")
    )


def test_files(repo: Path) -> list[Path]:
    return sorted(path for path in (repo / "tests").glob("test_*.py") if path.is_file())


def parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported_project_modules(tree: ast.AST, project_modules: set[str]) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in project_modules:
                    found.add(root)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root in project_modules:
                found.add(root)
    return found


def import_aliases(tree: ast.AST, project_modules: set[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in project_modules:
                    aliases[alias.asname or root] = root
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root not in project_modules:
                continue
            for alias in node.names:
                aliases[alias.asname or alias.name] = root
    return aliases


def domain_for_module(name: str) -> set[str]:
    result = {
        domain
        for domain, prefixes in DOMAIN_PREFIXES.items()
        if any(name == prefix or name.startswith(prefix + "_") for prefix in prefixes)
    }
    return result


def referenced_names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def multi_authority_functions(
    module: str, tree: ast.AST, project_modules: set[str]
) -> list[dict[str, object]]:
    aliases = import_aliases(tree, project_modules)
    result: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        refs = referenced_names(node)
        imported = sorted({aliases[name] for name in refs if name in aliases})
        domains = sorted(set().union(*(domain_for_module(item) for item in imported)) if imported else set())
        unclassified = sorted(item for item in imported if not domain_for_module(item))
        if len(domains) >= 2:
            result.append(
                {
                    "module": module,
                    "function": node.name,
                    "lineno": node.lineno,
                    "authority_domains": domains,
                    "project_dependencies": imported,
                    "unclassified_dependencies": unclassified,
                }
            )
    return sorted(result, key=lambda item: (str(item["module"]), int(item["lineno"]), str(item["function"])))


def tarjan_scc(graph: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for target in sorted(graph[node]):
            if target not in indices:
                strongconnect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(sorted(component))

    for node in sorted(graph):
        if node not in indices:
            strongconnect(node)
    return sorted(components, key=lambda members: (-len(members), members))


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def cochange(repo: Path, modules_by_path: dict[str, str], max_commits: int) -> dict[str, object]:
    raw = git(repo, "log", f"-n{max_commits}", "--format=COMMIT:%H", "--name-only", "--", "src")
    commits: list[set[str]] = []
    current: set[str] = set()
    observed_commits = 0
    for line in raw.splitlines():
        if line.startswith("COMMIT:"):
            if current:
                commits.append(current)
            current = set()
            observed_commits += 1
            continue
        rel = line.strip()
        if rel in modules_by_path:
            current.add(modules_by_path[rel])
    if current:
        commits.append(current)

    pairs: Counter[tuple[str, str]] = Counter()
    module_commits: Counter[str] = Counter()
    for changed in commits:
        for module in changed:
            module_commits[module] += 1
        for left, right in itertools.combinations(sorted(changed), 2):
            pairs[(left, right)] += 1

    top_pairs = [
        {"modules": [left, right], "cochange_commits": count}
        for (left, right), count in pairs.most_common(50)
    ]
    return {
        "requested_commit_limit": max_commits,
        "git_commits_observed": observed_commits,
        "commits_with_project_source_changes": len(commits),
        "top_pairs": top_pairs,
        "module_change_counts": [
            {"module": module, "commits": count}
            for module, count in module_commits.most_common()
        ],
    }


def test_coupling(repo: Path, project_modules: set[str]) -> dict[str, object]:
    module_to_tests: dict[str, list[str]] = defaultdict(list)
    tests: list[dict[str, object]] = []
    for path in test_files(repo):
        deps = sorted(imported_project_modules(parse(path), project_modules))
        if not deps:
            continue
        rel = path.relative_to(repo).as_posix()
        tests.append({"test_file": rel, "project_dependencies": deps, "dependency_count": len(deps)})
        for dep in deps:
            module_to_tests[dep].append(rel)
    return {
        "test_files_with_project_imports": len(tests),
        "most_crosscutting_tests": sorted(
            tests, key=lambda item: (-int(item["dependency_count"]), str(item["test_file"]))
        )[:50],
        "modules_by_test_fan_in": [
            {"module": module, "test_file_count": len(paths), "test_files": sorted(paths)}
            for module, paths in sorted(module_to_tests.items(), key=lambda item: (-len(item[1]), item[0]))
        ],
    }


def classification_coverage(
    graph: dict[str, set[str]], incoming: dict[str, set[str]]
) -> dict[str, object]:
    classified: list[str] = []
    unclassified: list[dict[str, object]] = []
    domain_counts: Counter[str] = Counter()
    for name in sorted(graph):
        domains = sorted(domain_for_module(name))
        if domains:
            classified.append(name)
            domain_counts.update(domains)
            continue
        unclassified.append(
            {
                "module": name,
                "fan_in": len(incoming[name]),
                "fan_out": len(graph[name]),
            }
        )

    ratio = len(classified) / len(graph) if graph else 1.0
    ranked_unknowns = sorted(
        unclassified,
        key=lambda item: (
            -(int(item["fan_in"]) + int(item["fan_out"])),
            -int(item["fan_in"]),
            -int(item["fan_out"]),
            str(item["module"]),
        ),
    )
    return {
        "classified_module_count": len(classified),
        "unclassified_module_count": len(unclassified),
        "classified_ratio": round(ratio, 6),
        "domain_module_counts": [
            {"domain": domain, "module_count": count}
            for domain, count in sorted(domain_counts.items())
        ],
        "unclassified_modules": [str(item["module"]) for item in unclassified],
        "unclassified_high_coupling": ranked_unknowns[:50],
    }


def build_baseline(repo: Path, max_commits: int) -> dict[str, object]:
    repo = repo.resolve()
    files = source_files(repo)
    modules = {module_name(path): path for path in files}
    project_modules = set(modules)
    trees = {name: parse(path) for name, path in modules.items()}
    graph = {
        name: imported_project_modules(trees[name], project_modules) - {name}
        for name in sorted(modules)
    }
    incoming: dict[str, set[str]] = {name: set() for name in modules}
    for source, targets in graph.items():
        for target in targets:
            incoming[target].add(source)

    sccs = tarjan_scc(graph)
    cyclic = [component for component in sccs if len(component) > 1]
    crosscutting = []
    multi_functions: list[dict[str, object]] = []
    for name in sorted(modules):
        domains = sorted(set().union(*(domain_for_module(dep) for dep in graph[name])) if graph[name] else set())
        if len(domains) >= 3:
            crosscutting.append(
                {
                    "module": name,
                    "authority_domains": domains,
                    "fan_out": len(graph[name]),
                    "dependencies": sorted(graph[name]),
                    "unclassified_dependencies": sorted(dep for dep in graph[name] if not domain_for_module(dep)),
                }
            )
        multi_functions.extend(multi_authority_functions(name, trees[name], project_modules))

    head = git(repo, "rev-parse", "HEAD").strip()
    dirty = bool(git(repo, "status", "--porcelain").strip())
    modules_by_path = {path.relative_to(repo).as_posix(): name for name, path in modules.items()}
    classification = classification_coverage(graph, incoming)
    evidence_gaps: list[dict[str, object]] = [
        {
            "kind": "reverse_import_classification",
            "reason": "No canonical layer contract is defined; guessing a layer order would turn a measurement into an architectural decision.",
            "needed_for": "hard reverse-import regression gate",
        },
        {
            "kind": "runtime_error_stack_frequency",
            "reason": "Repository analysis has no authoritative runtime/log corpus.",
            "needed_for": "ranking seams by observed production failure frequency",
        },
    ]
    if int(classification["unclassified_module_count"]) > 0:
        evidence_gaps.append(
            {
                "kind": "authority_domain_classification_coverage",
                "reason": "Modules outside the explicit descriptive prefix families remain unclassified rather than being assigned to an authority domain by guesswork.",
                "needed_for": "treating crosscutting-module and multi-authority-function rankings as complete authority coverage",
                "observed_unclassified_module_count": classification["unclassified_module_count"],
            }
        )

    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski-coupling-baseline-v1",
        "repository": str(repo),
        "git_head": head,
        "worktree_dirty": dirty,
        "measurement_contract": {
            "static_imports": "Python AST imports between top-level src/grabowski*.py modules",
            "scc": "Tarjan strongly connected components over the static import graph",
            "fan_in_out": "direct project-module import edges only",
            "crosscutting_module": "imports project modules classified into at least three authority-domain families",
            "multi_authority_function": "function references imported project aliases spanning at least two authority-domain families",
            "git_cochange": "same-commit co-change of project source modules over bounded first-parent-agnostic git history",
            "test_coupling": "static project-module imports from tests/test_*.py",
            "reverse_imports": "not classified without an explicit layer contract; raw directed edges are emitted instead",
            "runtime_stack_frequency": "not inferred from repository state; requires separately bound runtime/log evidence",
            "authority_classification": "prefix-based descriptive projection with explicit coverage; unknown modules remain unclassified rather than guessed",
        },
        "module_count": len(modules),
        "edge_count": sum(len(targets) for targets in graph.values()),
        "largest_scc_size": max((len(component) for component in sccs), default=0),
        "cyclic_scc_count": len(cyclic),
        "cyclic_sccs": cyclic,
        "fan_out": [
            {"module": name, "count": len(graph[name]), "dependencies": sorted(graph[name])}
            for name in sorted(graph, key=lambda item: (-len(graph[item]), item))
        ],
        "fan_in": [
            {"module": name, "count": len(incoming[name]), "dependents": sorted(incoming[name])}
            for name in sorted(incoming, key=lambda item: (-len(incoming[item]), item))
        ],
        "dependency_edges": [
            {"from": source, "to": target}
            for source in sorted(graph)
            for target in sorted(graph[source])
        ],
        "crosscutting_modules": sorted(
            crosscutting, key=lambda item: (-len(item["authority_domains"]), -int(item["fan_out"]), str(item["module"]))
        ),
        "multi_authority_functions": multi_functions,
        "authority_classification": classification,
        "git_cochange": cochange(repo, modules_by_path, max_commits),
        "test_coupling": test_coupling(repo, project_modules),
        "evidence_gaps": evidence_gaps,
    }
    digest_input = dict(report)
    report["report_sha256"] = sha256_bytes(canonical_json(digest_input))
    return report


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--max-commits", type=int, default=500)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.max_commits < 1 or args.max_commits > 10000:
        parser.error("--max-commits must be between 1 and 10000")
    report = build_baseline(args.repo, args.max_commits)
    payload = canonical_json(report)
    if args.output:
        args.output.write_bytes(payload)
    else:
        sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
