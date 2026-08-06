from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = 2
OBSERVED_AT = "2026-08-06T10:38:00Z"
PINNED_AGENT_FRAMEWORK_COMMIT = "422160eabec1776137ff33a7b8dada94d509fc56"
PINNED_AGENT_FRAMEWORK_REPOSITORY = "https://github.com/microsoft/agent-framework"

SCORE_KEYS = (
    "authorization",
    "technical_fit",
    "compensation",
    "time_efficiency",
    "duplicate_resilience",
    "local_verifiability",
)
SCORE_WEIGHTS = {
    "authorization": 4,
    "technical_fit": 4,
    "compensation": 2,
    "time_efficiency": 2,
    "duplicate_resilience": 2,
    "local_verifiability": 4,
}
COMPENSATION_PATHS = frozenset({"explicit", "tier-dependent", "post-merge"})
OFFICIAL_SOURCE_HOSTS = frozenset(
    {
        "about.gitlab.com",
        "bounty.github.com",
        "bughunters.google.com",
        "docs.github.com",
        "github.com",
        "hackerone.com",
        "www.microsoft.com",
        "www.mozilla.org",
    }
)

_PROGRAMS: tuple[dict[str, Any], ...] = (
    {
        "id": "microsoft-oss-bounty",
        "name": "Microsoft Open Source Bounty Program",
        "focus": "Microsoft Agent Framework and other explicitly listed Microsoft OSS",
        "authorization": (
            "Microsoft explicitly lists Microsoft Agent Framework and invites qualifying "
            "Critical or Important reports against the latest maintained branch."
        ),
        "scope": (
            "Eligible Microsoft-owned open-source repositories and qualifying third-party "
            "components included in the named service."
        ),
        "in_scope": ["Microsoft Agent Framework"],
        "out_of_scope": [
            "microsoft/semantic-kernel",
            "microsoft/autogen",
            "samples, tutorials, quickstarts, demos and experimental components",
            (
                "pickle checkpoint injection that already requires attacker write access "
                "to the trusted checkpoint storage backend"
            ),
        ],
        "methods": [
            "passive public-source review",
            "local pinned-commit analysis without credentials or service traffic",
        ],
        "exclusions": [
            "no live-service probing in this pilot",
            "no test account creation in this pilot",
            "no report or disclosure without a later target-bound authorization",
        ],
        "submission": "MSRC Researcher Portal",
        "compensation": "Published awards range from USD 750 to USD 15,000.",
        "compensation_path": "explicit",
        "sources": [
            "https://www.microsoft.com/en-us/msrc/opensourcebountyprogram",
            (
                "https://github.com/microsoft/agent-framework/commit/"
                + PINNED_AGENT_FRAMEWORK_COMMIT
            ),
        ],
        "scores": {
            "authorization": 5,
            "technical_fit": 5,
            "compensation": 5,
            "time_efficiency": 4,
            "duplicate_resilience": 4,
            "local_verifiability": 5,
        },
    },
    {
        "id": "gitlab-bug-bounty",
        "name": "GitLab Bug Bounty Program",
        "focus": "The public GitLab product source and GitLab.com",
        "authorization": (
            "GitLab directs security researchers to its official HackerOne program for "
            "scope, rules of engagement and rewards."
        ),
        "scope": (
            "Qualifying vulnerabilities in GitLab itself or GitLab.com; third-party "
            "projects merely hosted on GitLab.com are not implicitly authorized."
        ),
        "in_scope": ["GitLab product", "GitLab.com"],
        "out_of_scope": [
            "unrelated third-party projects hosted on GitLab.com",
            "denial-of-service activity outside the published program rules",
        ],
        "methods": [
            "passive public-source review",
            "local GitLab Development Kit reproduction after separate approval",
        ],
        "exclusions": [
            "no third-party project testing",
            "no public disclosure",
            "no external submission in this pilot",
        ],
        "submission": "GitLab HackerOne program",
        "compensation": "The current HackerOne severity table governs qualifying rewards.",
        "compensation_path": "explicit",
        "sources": [
            "https://about.gitlab.com/security/disclosure/",
            "https://hackerone.com/gitlab",
        ],
        "scores": {
            "authorization": 5,
            "technical_fit": 5,
            "compensation": 4,
            "time_efficiency": 3,
            "duplicate_resilience": 3,
            "local_verifiability": 5,
        },
    },
    {
        "id": "mozilla-client-bounty",
        "name": "Mozilla Client Security Bug Bounty",
        "focus": "Current Firefox desktop and mobile clients",
        "authorization": (
            "Mozilla publishes eligibility, safe-harbor and confidential-reporting rules "
            "for its client program."
        ),
        "scope": (
            "Current Mozilla releases and development versions of Firefox, Firefox for "
            "Android and Firefox for iOS."
        ),
        "in_scope": ["Firefox", "Firefox for Android", "Firefox for iOS"],
        "out_of_scope": [
            "end-of-life products",
            "third-party software not bundled by Mozilla",
        ],
        "methods": [
            "passive Mozilla-source review",
            "local proof against an official build after separate approval",
        ],
        "exclusions": [
            "no end-of-life target",
            "no unsupported build as the sole reproducer",
            "no premature disclosure",
        ],
        "submission": "Mozilla confidential security-bug reporting process",
        "compensation": (
            "Published rewards for qualifying high or critical client findings range "
            "from USD 3,000 to USD 20,000."
        ),
        "compensation_path": "explicit",
        "sources": [
            "https://www.mozilla.org/en-US/security/client-bug-bounty/",
            "https://www.mozilla.org/en-US/security/bug-bounty/",
            "https://www.mozilla.org/en-US/security/bug-bounty/faq/",
        ],
        "scores": {
            "authorization": 5,
            "technical_fit": 4,
            "compensation": 4,
            "time_efficiency": 3,
            "duplicate_resilience": 3,
            "local_verifiability": 5,
        },
    },
    {
        "id": "google-patch-rewards",
        "name": "Google Patch Rewards Program",
        "focus": "Proactive security improvements in listed or OSS-Fuzz projects",
        "authorization": (
            "Google accepts demonstrable proactive security improvements in explicitly "
            "in-scope open-source projects."
        ),
        "scope": (
            "Tier 1 projects on Google's published list, projects receiving a Google "
            "security report, and Tier 2 projects integrated into OSS-Fuzz."
        ),
        "in_scope": [
            "listed Tier 1 projects",
            "projects receiving a Google vulnerability report",
            "OSS-Fuzz projects",
        ],
        "out_of_scope": [
            "projects outside the published tiers",
            "patches not accepted by maintainers",
            "patches reverted within the required one-month period",
        ],
        "methods": [
            "passive source triage",
            "local design and test analysis before any contribution",
        ],
        "exclusions": [
            "no submission before a patch has remained merged for one month",
            "no more than the published monthly submission limit",
            "no maintainer contact in this pilot",
        ],
        "submission": "Google Patch Rewards form after maintainer acceptance and aging",
        "compensation": "Qualifying rewards range from USD 100 to USD 15,000.",
        "compensation_path": "post-merge",
        "sources": [
            "https://bughunters.google.com/about/rules/open-source/patch-rewards-program-rules",
            "https://bughunters.google.com/open-source-security/patch-rewards",
        ],
        "scores": {
            "authorization": 5,
            "technical_fit": 4,
            "compensation": 5,
            "time_efficiency": 2,
            "duplicate_resilience": 4,
            "local_verifiability": 4,
        },
    },
    {
        "id": "github-bug-bounty",
        "name": "GitHub Bug Bounty",
        "focus": "GitHub services and explicitly listed products",
        "authorization": "GitHub publishes scope, rules, rewards and legal safe harbor.",
        "scope": (
            "Listed GitHub domains and products such as CLI, Desktop, Mobile and "
            "Enterprise; arbitrary GitHub-owned repositories are not automatically eligible."
        ),
        "in_scope": ["products and domains listed by GitHub's current scope"],
        "out_of_scope": [
            "unlisted third-party subdomains",
            "arbitrary repositories solely because GitHub owns the organization",
        ],
        "methods": [
            "passive review of an explicitly in-scope open-source client",
            "local exact-version reproduction after separate approval",
        ],
        "exclusions": [
            "no social engineering",
            "no access to other users' data",
            "no external submission in this pilot",
        ],
        "submission": "GitHub bounty submission path",
        "compensation": "Published guidance ranges from USD 617 to USD 30,000 or more.",
        "compensation_path": "explicit",
        "sources": [
            "https://bounty.github.com/",
            "https://bounty.github.com/scope",
            "https://bounty.github.com/rules.html",
            "https://bounty.github.com/rewards",
            (
                "https://docs.github.com/en/site-policy/security-policies/"
                "github-bug-bounty-program-legal-safe-harbor"
            ),
        ],
        "scores": {
            "authorization": 5,
            "technical_fit": 4,
            "compensation": 5,
            "time_efficiency": 3,
            "duplicate_resilience": 2,
            "local_verifiability": 4,
        },
    },
    {
        "id": "google-oss-vrp",
        "name": "Google Open Source Software Vulnerability Rewards Program",
        "focus": "Google-owned public open-source repositories",
        "authorization": (
            "Google authorizes good-faith research and confidential reports for the latest "
            "versions of Google OSS."
        ),
        "scope": (
            "Public repositories in Google-owned GitHub organizations, selected external "
            "repositories, repository configuration and qualifying dependencies."
        ),
        "in_scope": [
            "latest Google-owned public repositories",
            "selected external repositories",
            "repository configuration and qualifying dependencies",
        ],
        "out_of_scope": [
            "OT3 projects for financial rewards",
            "OT2 product vulnerabilities for financial rewards",
            "duplicate root causes",
        ],
        "methods": [
            "passive public-source review",
            "local pinned-version reproduction after separate approval",
        ],
        "exclusions": [
            "no production traffic",
            "no speculative or unvalidated AI report",
            "no external submission in this pilot",
        ],
        "submission": "Google Bug Hunters form with OSS VRP selected",
        "compensation": (
            "Rewards are tier- and impact-dependent; OT2 product vulnerabilities have no "
            "published financial reward, while qualifying supply-chain issues may be rewarded."
        ),
        "compensation_path": "tier-dependent",
        "sources": [
            "https://bughunters.google.com/open-source-security",
            (
                "https://bughunters.google.com/about/rules/open-source/"
                "google-open-source-software-vulnerability-reward-program-rules"
            ),
            "https://bughunters.google.com/blog/ossvrp-rule-updates-2026",
        ],
        "scores": {
            "authorization": 5,
            "technical_fit": 3,
            "compensation": 2,
            "time_efficiency": 3,
            "duplicate_resilience": 3,
            "local_verifiability": 5,
        },
    },
)

_PLAN: dict[str, Any] = {
    "program_id": "microsoft-oss-bounty",
    "repository": PINNED_AGENT_FRAMEWORK_REPOSITORY,
    "exact_commit": PINNED_AGENT_FRAMEWORK_COMMIT,
    "target": (
        "Untrusted serialization, checkpoint, tool, plugin and workflow boundaries in "
        "Microsoft Agent Framework"
    ),
    "time_budget_hours": 4,
    "allowed_analysis": [
        "read public source, tests, dependencies, policy and history locally",
        "run existing tests without model, cloud or service credentials",
        "use static search and type-aware reasoning",
        "write a local regression test only for a concrete code path",
    ],
    "stop_conditions": [
        "scope or exact commit cannot be verified",
        "production traffic, accounts, credentials, paid services or third-party data are required",
        "candidate depends on speculative model behavior",
        "candidate matches a published out-of-scope scenario",
        "time budget expires without local reproducibility",
    ],
    "excluded_scenarios": [
        (
            "pickle checkpoint injection requiring attacker write access to the trusted "
            "checkpoint storage backend"
        ),
        "samples, tutorials, quickstarts, demos and experimental components",
    ],
    "non_claims": [
        "no vulnerability is asserted",
        "no production testing is authorized",
        "no account, submission, disclosure or publication is authorized",
        "no reward entitlement is established",
    ],
    "active_target_requests": 0,
    "external_submissions": 0,
    "additional_cost_eur": 0,
}

_BOUNDARIES = (
    "public-information-and-public-source-only",
    "no-active-target-traffic",
    "no-account-creation",
    "no-external-submission",
    "no-publication",
    "zero-additional-cost",
    "separate-target-bound-authorization-required-for-external-effect",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def program_score(program: dict[str, Any]) -> int:
    scores = program["scores"]
    return sum(SCORE_WEIGHTS[key] * scores[key] for key in SCORE_KEYS)


def ranked_programs(
    programs: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> list[dict[str, Any]]:
    values = _PROGRAMS if programs is None else programs
    return sorted(
        deepcopy(list(values)),
        key=lambda item: (-program_score(item), item["id"]),
    )


def build_pilot_bundle() -> dict[str, Any]:
    programs = deepcopy(list(_PROGRAMS))
    for program in programs:
        program["observed_at"] = OBSERVED_AT
    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": OBSERVED_AT,
        "programs": programs,
        "ranking": [item["id"] for item in ranked_programs(programs)],
        "local_review_plans": [deepcopy(_PLAN)],
        "pilot_boundaries": list(_BOUNDARIES),
    }


def bundle_digests(bundle: dict[str, Any] | None = None) -> dict[str, str]:
    selected = build_pilot_bundle() if bundle is None else bundle
    validate_pilot_bundle(selected)
    by_id = {item["id"]: item for item in selected["programs"]}
    ranking = [
        {
            "id": item_id,
            "score": program_score(by_id[item_id]),
            "scores": by_id[item_id]["scores"],
        }
        for item_id in selected["ranking"]
    ]
    return {
        "catalog_sha256": digest(selected["programs"]),
        "ranking_sha256": digest(ranking),
        "local_review_plan_sha256": digest(selected["local_review_plans"]),
        "bundle_sha256": digest(selected),
    }


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _require_text_list(value: Any, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{label} must be a non-empty unique text list")
    return value


def _require_https_authority(url: str, *, label: str) -> None:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in OFFICIAL_SOURCE_HOSTS
        or parsed.username
        or parsed.password
    ):
        raise ValueError(f"unapproved {label}: {url}")


def validate_pilot_bundle(bundle: dict[str, Any] | None = None) -> None:
    selected = build_pilot_bundle() if bundle is None else bundle
    required_top = {
        "schema_version",
        "observed_at",
        "programs",
        "ranking",
        "local_review_plans",
        "pilot_boundaries",
    }
    if not isinstance(selected, dict) or set(selected) != required_top:
        raise ValueError("catalog top-level contract mismatch")
    if selected["schema_version"] != SCHEMA_VERSION:
        raise ValueError("catalog schema version mismatch")
    if not isinstance(selected["programs"], list) or len(selected["programs"]) < 5:
        raise ValueError("catalog requires at least five programs")
    observed = _utc(selected["observed_at"])
    if observed > datetime.now(timezone.utc):
        raise ValueError("future observation")

    required_program = {
        "id",
        "name",
        "focus",
        "authorization",
        "scope",
        "in_scope",
        "out_of_scope",
        "methods",
        "exclusions",
        "submission",
        "compensation",
        "compensation_path",
        "observed_at",
        "sources",
        "scores",
    }
    ids: set[str] = set()
    by_id: dict[str, dict[str, Any]] = {}
    for program in selected["programs"]:
        if not isinstance(program, dict) or set(program) != required_program:
            raise ValueError("invalid program shape")
        program_id = program["id"]
        if (
            not isinstance(program_id, str)
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", program_id) is None
            or program_id in ids
        ):
            raise ValueError("invalid or duplicate program id")
        ids.add(program_id)
        by_id[program_id] = program
        for key in (
            "name",
            "focus",
            "authorization",
            "scope",
            "submission",
            "compensation",
        ):
            if not isinstance(program[key], str) or not program[key].strip():
                raise ValueError(f"incomplete evidence: {program_id}")
        for key in ("in_scope", "out_of_scope", "methods", "exclusions", "sources"):
            _require_text_list(program[key], label=f"{program_id}.{key}")
        if _utc(program["observed_at"]) != observed:
            raise ValueError(f"observation drift: {program_id}")
        if program["compensation_path"] not in COMPENSATION_PATHS:
            raise ValueError(f"invalid compensation path: {program_id}")
        for url in program["sources"]:
            _require_https_authority(url, label="source")
        scores = program["scores"]
        if (
            not isinstance(scores, dict)
            or tuple(scores) != SCORE_KEYS
            or any(
                type(scores[key]) is not int or not 1 <= scores[key] <= 5
                for key in SCORE_KEYS
            )
        ):
            raise ValueError(f"invalid ranking inputs: {program_id}")

    ranking = selected["ranking"]
    if (
        not isinstance(ranking, list)
        or len(ranking) != len(ids)
        or len(set(ranking)) != len(ranking)
        or set(ranking) != ids
        or ranking != [item["id"] for item in ranked_programs(selected["programs"])]
    ):
        raise ValueError("ranking is not a deterministic program permutation")

    plans = selected["local_review_plans"]
    if not isinstance(plans, list) or len(plans) != 1:
        raise ValueError("exactly one local review plan is required")
    plan = plans[0]
    required_plan = {
        "program_id",
        "repository",
        "exact_commit",
        "target",
        "time_budget_hours",
        "allowed_analysis",
        "stop_conditions",
        "excluded_scenarios",
        "non_claims",
        "active_target_requests",
        "external_submissions",
        "additional_cost_eur",
    }
    if not isinstance(plan, dict) or set(plan) != required_plan:
        raise ValueError("local review plan contract mismatch")
    if plan["program_id"] not in by_id:
        raise ValueError("local review plan program is missing")
    program = by_id[plan["program_id"]]
    if program["compensation_path"] != "explicit":
        raise ValueError("local review plan requires an explicit compensation path")
    if "Microsoft Agent Framework" not in program["in_scope"]:
        raise ValueError("local review plan target lacks explicit scope evidence")
    if plan["repository"] != PINNED_AGENT_FRAMEWORK_REPOSITORY:
        raise ValueError("local review plan repository mismatch")
    _require_https_authority(plan["repository"], label="repository")
    if plan["exact_commit"] != PINNED_AGENT_FRAMEWORK_COMMIT or re.fullmatch(
        r"[0-9a-f]{40}", plan["exact_commit"]
    ) is None:
        raise ValueError("local review plan commit mismatch")
    if (
        type(plan["time_budget_hours"]) is not int
        or not 1 <= plan["time_budget_hours"] <= 8
    ):
        raise ValueError("local review plan time budget is invalid")
    for key in (
        "allowed_analysis",
        "stop_conditions",
        "excluded_scenarios",
        "non_claims",
    ):
        _require_text_list(plan[key], label=f"plan.{key}")
    if any(
        plan[key] != 0
        for key in (
            "active_target_requests",
            "external_submissions",
            "additional_cost_eur",
        )
    ):
        raise ValueError("active, external or paid effect")

    boundaries = _require_text_list(
        selected["pilot_boundaries"],
        label="pilot_boundaries",
    )
    required_boundaries = {
        "no-active-target-traffic",
        "no-account-creation",
        "no-external-submission",
        "no-publication",
        "zero-additional-cost",
        "separate-target-bound-authorization-required-for-external-effect",
    }
    if not required_boundaries.issubset(boundaries):
        raise ValueError("pilot boundaries incomplete")


def render_markdown(bundle: dict[str, Any] | None = None) -> str:
    selected = build_pilot_bundle() if bundle is None else bundle
    validate_pilot_bundle(selected)
    lines = [
        "# Autorisierter Bounty-Katalog v2",
        "",
        f"Beobachtet: `{selected['observed_at']}`",
        "",
        (
            "Der Pilot ist rein passiv: kein Zielsystemverkehr, kein Account, "
            "keine Meldung und keine Veröffentlichung."
        ),
        "",
        "## Revisionsbindung",
        "",
    ]
    lines.extend(
        f"- `{key}`: `{value}`"
        for key, value in bundle_digests(selected).items()
    )
    lines.extend(
        [
            "",
            "## Rangliste",
            "",
            "| Rang | Programm | Punkte | Vergütungspfad | Schwerpunkt |",
            "|---:|---|---:|---|---|",
        ]
    )
    by_id = {item["id"]: item for item in selected["programs"]}
    for rank, item_id in enumerate(selected["ranking"], 1):
        item = by_id[item_id]
        lines.append(
            f"| {rank} | {item['name']} | {program_score(item)} | "
            f"{item['compensation_path']} | {item['focus']} |"
        )

    lines.extend(["", "## Programme", ""])
    for item_id in selected["ranking"]:
        item = by_id[item_id]
        lines.extend(
            [
                f"### {item['name']}",
                "",
                f"- **Autorisierung:** {item['authorization']}",
                f"- **Scope:** {item['scope']}",
                f"- **Einreichung:** {item['submission']}",
                f"- **Vergütung:** {item['compensation']}",
                f"- **Vergütungspfad:** `{item['compensation_path']}`",
                f"- **Beobachtet:** `{item['observed_at']}`",
                "- **Explizit im Scope:**",
            ]
        )
        lines.extend(f"  - {value}" for value in item["in_scope"])
        lines.append("- **Explizit oder praktisch ausgeschlossen:**")
        lines.extend(f"  - {value}" for value in item["out_of_scope"])
        lines.append("- **Erlaubte Methoden:**")
        lines.extend(f"  - {value}" for value in item["methods"])
        lines.append("- **Ausschlüsse des Piloten:**")
        lines.extend(f"  - {value}" for value in item["exclusions"])
        lines.append("- **Offizielle Quellen:**")
        lines.extend(f"  - {value}" for value in item["sources"])
        lines.append("")

    plan = selected["local_review_plans"][0]
    lines.extend(
        [
            "## Genau ein lokaler Prüfplan",
            "",
            f"- **Programm:** `{plan['program_id']}`",
            f"- **Repository:** {plan['repository']}",
            f"- **Exakter Commit:** `{plan['exact_commit']}`",
            f"- **Zeitbudget:** {plan['time_budget_hours']} Stunden",
            f"- **Ziel:** {plan['target']}",
            "- **Erlaubte Analyse:**",
        ]
    )
    lines.extend(f"  - {value}" for value in plan["allowed_analysis"])
    lines.append("- **Abbruchkriterien:**")
    lines.extend(f"  - {value}" for value in plan["stop_conditions"])
    lines.append("- **Ausgeschlossene Szenarien:**")
    lines.extend(f"  - {value}" for value in plan["excluded_scenarios"])
    lines.append("- **Non-Claims:**")
    lines.extend(f"  - {value}" for value in plan["non_claims"])
    lines.extend(["", "## Pilotgrenzen", ""])
    lines.extend(f"- `{value}`" for value in selected["pilot_boundaries"])
    lines.extend(
        [
            "",
            (
                "Jede externe Wirkung benötigt einen separaten zielgebundenen Auftrag "
                "und einen frischen Scope-Readback."
            ),
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    validate_pilot_bundle()
    print(json.dumps(bundle_digests(), sort_keys=True))
