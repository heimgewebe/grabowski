from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = 1
OBSERVED_AT = "2026-08-06T09:49:58Z"
PINNED_ADK_COMMIT = "6ccb83734ed22e79737406a54a9a205f3feed0ab"
SCORE_KEYS = ("authorization", "technical_fit", "compensation", "time_efficiency", "duplicate_resilience", "local_verifiability")
SCORE_WEIGHTS = (4, 4, 2, 2, 2, 4)
OFFICIAL_HOSTS = frozenset({"about.gitlab.com", "bounty.github.com", "bugcrowd.com", "bughunters.google.com", "docs.github.com", "hackerone.com", "openai.com", "www.mozilla.org"})

_PROGRAMS: tuple[dict[str, Any], ...] = (
    {
        "id": "google-oss-vrp",
        "name": "Google Open Source Software Vulnerability Rewards Program",
        "focus": "Google-owned open-source repositories, including AI-agent projects",
        "authorization": "Official OSS VRP rules authorize good-faith research and confidential reporting.",
        "scope": "Latest public Google-owned repositories, selected repositories, configuration and qualifying dependencies.",
        "methods": ["passive public-source review", "local pinned-version reproduction after separate approval"],
        "exclusions": ["no production traffic", "no unvalidated AI report", "no duplicate root cause"],
        "submission": "Google Bug Hunters form with OSS VRP selected",
        "compensation": "Published ranges reach USD 31,337 for flagship supply-chain compromises; current tables govern other classes.",
        "sources": ["https://bughunters.google.com/open-source-security", "https://bughunters.google.com/about/rules/open-source/google-open-source-software-vulnerability-reward-program-rules", "https://bughunters.google.com/blog/ossvrp-rule-updates-2026"],
        "scores": [5, 5, 5, 4, 3, 5],
    },
    {
        "id": "gitlab-bug-bounty",
        "name": "GitLab Bug Bounty Program",
        "focus": "Public GitLab product source and GitLab.com",
        "authorization": "GitLab directs researchers to its official HackerOne scope and rules.",
        "scope": "Qualifying GitLab product or GitLab.com issues; hosted third-party projects are not implicitly authorized.",
        "methods": ["passive source review", "local exact-version tests after separate approval"],
        "exclusions": ["no third-party project testing", "no denial of service", "no public disclosure"],
        "submission": "GitLab HackerOne; confidential issue only as documented fallback",
        "compensation": "Current HackerOne severity table governs rewards; the fallback route is not a compensation path.",
        "sources": ["https://about.gitlab.com/security/disclosure/", "https://hackerone.com/gitlab"],
        "scores": [5, 5, 4, 3, 3, 5],
    },
    {
        "id": "mozilla-client-bounty",
        "name": "Mozilla Client Security Bug Bounty",
        "focus": "Current Firefox desktop and mobile clients",
        "authorization": "Mozilla publishes eligibility, safe-harbor and confidential-reporting rules.",
        "scope": "Current official Firefox, Firefox for Android and Firefox for iOS versions.",
        "methods": ["passive Mozilla-source review", "local proof against an official build after separate approval"],
        "exclusions": ["no end-of-life target", "no unsupported build as sole reproducer", "no premature disclosure"],
        "submission": "Mozilla confidential security-bug reporting process",
        "compensation": "Published client rewards range from USD 3,000 to USD 20,000 for qualifying high or critical findings.",
        "sources": ["https://www.mozilla.org/en-US/security/client-bug-bounty/", "https://www.mozilla.org/en-US/security/bug-bounty/", "https://www.mozilla.org/en-US/security/bug-bounty/faq/"],
        "scores": [5, 4, 4, 3, 3, 5],
    },
    {
        "id": "github-bug-bounty",
        "name": "GitHub Bug Bounty",
        "focus": "GitHub services and explicitly listed products, including selected open-source clients",
        "authorization": "GitHub publishes scope, rules, rewards and legal safe harbor.",
        "scope": "Listed domains and products such as CLI, Desktop, Mobile and Enterprise; arbitrary GitHub-owned repositories are not automatically eligible.",
        "methods": ["passive in-scope client-source review", "local exact-version reproduction after separate approval"],
        "exclusions": ["no third-party subdomain", "no social engineering", "no access to others' data"],
        "submission": "GitHub bounty submission path linked from bounty.github.com",
        "compensation": "Published guidance ranges from USD 617 to USD 30,000 or more.",
        "sources": ["https://bounty.github.com/", "https://bounty.github.com/scope", "https://bounty.github.com/rules.html", "https://bounty.github.com/rewards", "https://docs.github.com/en/site-policy/security-policies/github-bug-bounty-program-legal-safe-harbor"],
        "scores": [5, 4, 5, 3, 2, 4],
    },
    {
        "id": "openai-security-bounty",
        "name": "OpenAI Security Bug Bounty",
        "focus": "OpenAI security issues under the current Bugcrowd program",
        "authorization": "OpenAI's disclosure policy invites qualifying reports through Bugcrowd.",
        "scope": "Systems in the current Bugcrowd rules; generic jailbreak and safety-abuse reports use different programs.",
        "methods": ["passive public-artifact review", "local exact-artifact analysis after separate approval"],
        "exclusions": ["no account creation", "no live-service testing", "no report without separate authorization"],
        "submission": "OpenAI Bugcrowd program linked by the official policy",
        "compensation": "OpenAI announced rewards up to USD 100,000 for exceptional and differentiated critical findings; current program rules govern other tiers.",
        "sources": ["https://openai.com/index/security-on-the-path-to-agi/", "https://openai.com/policies/coordinated-vulnerability-disclosure-policy/", "https://bugcrowd.com/openai"],
        "scores": [5, 4, 4, 2, 2, 2],
    },
)

_PLAN: dict[str, Any] = {
    "program_id": "google-oss-vrp",
    "repository": "https://github.com/google/adk-python",
    "exact_commit": PINNED_ADK_COMMIT,
    "target": "Agent tool, plugin, session and serialization trust boundaries in Google ADK Python",
    "time_budget_hours": 6,
    "allowed_analysis": ["read public source, tests, dependencies, policy and history locally", "run existing tests without model or cloud credentials", "use static search and type-aware reasoning", "write a local regression test only for a concrete code path"],
    "stop_conditions": ["scope or commit cannot be verified", "production traffic, credentials, paid services or third-party data are required", "candidate depends on speculative model behavior", "budget expires without local reproducibility"],
    "non_claims": ["no vulnerability is asserted", "no production testing is authorized", "no account, submission, disclosure or publication is authorized", "no reward entitlement is established"],
    "active_target_requests": 0,
    "external_submissions": 0,
    "additional_cost_eur": 0,
}

_BOUNDARIES = ("public-information-and-public-source-only", "no-active-target-traffic", "no-account-creation", "no-external-submission", "no-publication", "zero-additional-cost", "separate-target-bound-authorization-required-for-external-effect")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def program_score(program: dict[str, Any]) -> int:
    return sum(weight * value for weight, value in zip(SCORE_WEIGHTS, program["scores"], strict=True))


def ranked_programs(programs: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None) -> list[dict[str, Any]]:
    values = programs if programs is not None else _PROGRAMS
    return sorted(deepcopy(list(values)), key=lambda item: (-program_score(item), item["id"]))


def build_pilot_bundle() -> dict[str, Any]:
    programs = deepcopy(list(_PROGRAMS))
    for program in programs:
        program["observed_at"] = OBSERVED_AT
    return {"schema_version": SCHEMA_VERSION, "observed_at": OBSERVED_AT, "programs": programs, "ranking": [item["id"] for item in ranked_programs(programs)], "local_review_plans": [deepcopy(_PLAN)], "pilot_boundaries": list(_BOUNDARIES)}


def bundle_digests(bundle: dict[str, Any] | None = None) -> dict[str, str]:
    bundle = bundle or build_pilot_bundle()
    by_id = {item["id"]: item for item in bundle["programs"]}
    ranking = [{"id": item_id, "score": program_score(by_id[item_id]), "scores": dict(zip(SCORE_KEYS, by_id[item_id]["scores"], strict=True))} for item_id in bundle["ranking"]]
    return {"catalog_sha256": digest(bundle["programs"]), "ranking_sha256": digest(ranking), "local_review_plan_sha256": digest(bundle["local_review_plans"]), "bundle_sha256": digest(bundle)}


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def validate_pilot_bundle(bundle: dict[str, Any] | None = None) -> None:
    bundle = bundle or build_pilot_bundle()
    if bundle.get("schema_version") != SCHEMA_VERSION or len(bundle.get("programs", [])) < 5:
        raise ValueError("catalog contract mismatch")
    observed = _utc(bundle["observed_at"])
    if observed > datetime.now(timezone.utc):
        raise ValueError("future observation")
    ids: set[str] = set()
    required = {"id", "name", "focus", "authorization", "scope", "methods", "exclusions", "submission", "compensation", "observed_at", "sources", "scores"}
    for program in bundle["programs"]:
        if set(program) != required or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", program["id"]) or program["id"] in ids:
            raise ValueError("invalid program shape or id")
        ids.add(program["id"])
        if any(not program[key] for key in required) or _utc(program["observed_at"]) != observed:
            raise ValueError(f"incomplete evidence: {program['id']}")
        for url in program["sources"]:
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in OFFICIAL_HOSTS or parsed.username or parsed.password:
                raise ValueError(f"unapproved source: {url}")
        if len(program["scores"]) != len(SCORE_KEYS) or any(not isinstance(value, int) or not 1 <= value <= 5 for value in program["scores"]):
            raise ValueError(f"invalid ranking: {program['id']}")
    if bundle["ranking"] != [item["id"] for item in ranked_programs(bundle["programs"])] or len(bundle["local_review_plans"]) != 1:
        raise ValueError("ranking or plan cardinality mismatch")
    plan = bundle["local_review_plans"][0]
    if plan["program_id"] not in ids or not re.fullmatch(r"[0-9a-f]{40}", plan["exact_commit"]) or not 1 <= plan["time_budget_hours"] <= 8:
        raise ValueError("plan is not program-, commit-, and budget-bound")
    if any(plan[key] != 0 for key in ("active_target_requests", "external_submissions", "additional_cost_eur")):
        raise ValueError("active, external or paid effect")
    if not {"no-active-target-traffic", "no-account-creation", "no-external-submission", "no-publication", "zero-additional-cost"}.issubset(bundle["pilot_boundaries"]):
        raise ValueError("pilot boundaries incomplete")


def render_markdown(bundle: dict[str, Any] | None = None) -> str:
    bundle = bundle or build_pilot_bundle()
    validate_pilot_bundle(bundle)
    lines = ["# Autorisierter Bounty-Katalog v1", "", f"Beobachtet: `{bundle['observed_at']}`", "", "Der Pilot ist rein passiv: kein Zielsystemverkehr, kein Account, keine Meldung und keine Veröffentlichung.", "", "## Revisionsbindung", ""]
    lines.extend(f"- `{key}`: `{value}`" for key, value in bundle_digests(bundle).items())
    lines.extend(["", "## Rangliste", "", "| Rang | Programm | Punkte | Schwerpunkt |", "|---:|---|---:|---|"])
    by_id = {item["id"]: item for item in bundle["programs"]}
    for rank, item_id in enumerate(bundle["ranking"], 1):
        item = by_id[item_id]
        lines.append(f"| {rank} | {item['name']} | {program_score(item)} | {item['focus']} |")
    lines.extend(["", "## Programme", ""])
    for item_id in bundle["ranking"]:
        item = by_id[item_id]
        lines.extend([f"### {item['name']}", "", f"- **Autorisierung:** {item['authorization']}", f"- **Scope:** {item['scope']}", f"- **Einreichung:** {item['submission']}", f"- **Vergütung:** {item['compensation']}", f"- **Beobachtet:** `{item['observed_at']}`", "- **Erlaubte Methoden:**"])
        lines.extend(f"  - {value}" for value in item["methods"])
        lines.append("- **Ausschlüsse:**")
        lines.extend(f"  - {value}" for value in item["exclusions"])
        lines.append("- **Offizielle Quellen:**")
        lines.extend(f"  - {value}" for value in item["sources"])
        lines.append("")
    plan = bundle["local_review_plans"][0]
    lines.extend(["## Genau ein lokaler Prüfplan", "", f"- **Programm:** `{plan['program_id']}`", f"- **Repository:** {plan['repository']}", f"- **Exakter Commit:** `{plan['exact_commit']}`", f"- **Zeitbudget:** {plan['time_budget_hours']} Stunden", f"- **Ziel:** {plan['target']}", "- **Erlaubte Analyse:**"])
    lines.extend(f"  - {value}" for value in plan["allowed_analysis"])
    lines.append("- **Abbruchkriterien:**")
    lines.extend(f"  - {value}" for value in plan["stop_conditions"])
    lines.append("- **Non-Claims:**")
    lines.extend(f"  - {value}" for value in plan["non_claims"])
    lines.extend(["", "## Pilotgrenzen", ""])
    lines.extend(f"- `{value}`" for value in bundle["pilot_boundaries"])
    lines.extend(["", "Jede externe Wirkung benötigt einen separaten zielgebundenen Auftrag und einen frischen Scope-Readback.", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    validate_pilot_bundle()
    print(json.dumps(bundle_digests(), sort_keys=True))
