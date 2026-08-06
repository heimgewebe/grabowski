# Autorisierter Bounty-Katalog v2

Beobachtet: `2026-08-06T10:38:00Z`

Der Pilot ist rein passiv: kein Zielsystemverkehr, kein Account, keine Meldung und keine Veröffentlichung.

## Revisionsbindung

- `catalog_sha256`: `460889c9361d71e955d20e4dd2a131c50a408e17790f434c1997730379677260`
- `ranking_sha256`: `591f60986941f5f4e382616d82dea90edc15fafd26ae98b511936aa2a1006580`
- `local_review_plan_sha256`: `ca2a6cf355a8872c409c7811156a6a3c98646cba2b8e6da71c80e1aa40857d11`
- `bundle_sha256`: `88362e016443f516390e27ab4128fcedf3c29c408ef2a352abfa16b72763b182`

## Rangliste

| Rang | Programm | Punkte | Vergütungspfad | Schwerpunkt |
|---:|---|---:|---|---|
| 1 | Microsoft Open Source Bounty Program | 86 | explicit | Microsoft Agent Framework and other explicitly listed Microsoft OSS |
| 2 | GitLab Bug Bounty Program | 80 | explicit | The public GitLab product source and GitLab.com |
| 3 | Mozilla Client Security Bug Bounty | 76 | explicit | Current Firefox desktop and mobile clients |
| 4 | Google Patch Rewards Program | 74 | post-merge | Proactive security improvements in listed or OSS-Fuzz projects |
| 5 | GitHub Bug Bounty | 72 | explicit | GitHub services and explicitly listed products |
| 6 | Google Open Source Software Vulnerability Rewards Program | 68 | tier-dependent | Google-owned public open-source repositories |

## Programme

### Microsoft Open Source Bounty Program

- **Autorisierung:** Microsoft explicitly lists Microsoft Agent Framework and invites qualifying Critical or Important reports against the latest maintained branch.
- **Scope:** Eligible Microsoft-owned open-source repositories and qualifying third-party components included in the named service.
- **Einreichung:** MSRC Researcher Portal
- **Vergütung:** Published awards range from USD 750 to USD 15,000.
- **Vergütungspfad:** `explicit`
- **Beobachtet:** `2026-08-06T10:38:00Z`
- **Explizit im Scope:**
  - Microsoft Agent Framework
- **Explizit oder praktisch ausgeschlossen:**
  - microsoft/semantic-kernel
  - microsoft/autogen
  - samples, tutorials, quickstarts, demos and experimental components
  - pickle checkpoint injection that already requires attacker write access to the trusted checkpoint storage backend
- **Erlaubte Methoden:**
  - passive public-source review
  - local pinned-commit analysis without credentials or service traffic
- **Ausschlüsse des Piloten:**
  - no live-service probing in this pilot
  - no test account creation in this pilot
  - no report or disclosure without a later target-bound authorization
- **Offizielle Quellen:**
  - https://www.microsoft.com/en-us/msrc/opensourcebountyprogram
  - https://github.com/microsoft/agent-framework/commit/422160eabec1776137ff33a7b8dada94d509fc56

### GitLab Bug Bounty Program

- **Autorisierung:** GitLab directs security researchers to its official HackerOne program for scope, rules of engagement and rewards.
- **Scope:** Qualifying vulnerabilities in GitLab itself or GitLab.com; third-party projects merely hosted on GitLab.com are not implicitly authorized.
- **Einreichung:** GitLab HackerOne program
- **Vergütung:** The current HackerOne severity table governs qualifying rewards.
- **Vergütungspfad:** `explicit`
- **Beobachtet:** `2026-08-06T10:38:00Z`
- **Explizit im Scope:**
  - GitLab product
  - GitLab.com
- **Explizit oder praktisch ausgeschlossen:**
  - unrelated third-party projects hosted on GitLab.com
  - denial-of-service activity outside the published program rules
- **Erlaubte Methoden:**
  - passive public-source review
  - local GitLab Development Kit reproduction after separate approval
- **Ausschlüsse des Piloten:**
  - no third-party project testing
  - no public disclosure
  - no external submission in this pilot
- **Offizielle Quellen:**
  - https://about.gitlab.com/security/disclosure/
  - https://hackerone.com/gitlab

### Mozilla Client Security Bug Bounty

- **Autorisierung:** Mozilla publishes eligibility, safe-harbor and confidential-reporting rules for its client program.
- **Scope:** Current Mozilla releases and development versions of Firefox, Firefox for Android and Firefox for iOS.
- **Einreichung:** Mozilla confidential security-bug reporting process
- **Vergütung:** Published rewards for qualifying high or critical client findings range from USD 3,000 to USD 20,000.
- **Vergütungspfad:** `explicit`
- **Beobachtet:** `2026-08-06T10:38:00Z`
- **Explizit im Scope:**
  - Firefox
  - Firefox for Android
  - Firefox for iOS
- **Explizit oder praktisch ausgeschlossen:**
  - end-of-life products
  - third-party software not bundled by Mozilla
- **Erlaubte Methoden:**
  - passive Mozilla-source review
  - local proof against an official build after separate approval
- **Ausschlüsse des Piloten:**
  - no end-of-life target
  - no unsupported build as the sole reproducer
  - no premature disclosure
- **Offizielle Quellen:**
  - https://www.mozilla.org/en-US/security/client-bug-bounty/
  - https://www.mozilla.org/en-US/security/bug-bounty/
  - https://www.mozilla.org/en-US/security/bug-bounty/faq/

### Google Patch Rewards Program

- **Autorisierung:** Google accepts demonstrable proactive security improvements in explicitly in-scope open-source projects.
- **Scope:** Tier 1 projects on Google's published list, projects receiving a Google security report, and Tier 2 projects integrated into OSS-Fuzz.
- **Einreichung:** Google Patch Rewards form after maintainer acceptance and aging
- **Vergütung:** Qualifying rewards range from USD 100 to USD 15,000.
- **Vergütungspfad:** `post-merge`
- **Beobachtet:** `2026-08-06T10:38:00Z`
- **Explizit im Scope:**
  - listed Tier 1 projects
  - projects receiving a Google vulnerability report
  - OSS-Fuzz projects
- **Explizit oder praktisch ausgeschlossen:**
  - projects outside the published tiers
  - patches not accepted by maintainers
  - patches reverted within the required one-month period
- **Erlaubte Methoden:**
  - passive source triage
  - local design and test analysis before any contribution
- **Ausschlüsse des Piloten:**
  - no submission before a patch has remained merged for one month
  - no more than the published monthly submission limit
  - no maintainer contact in this pilot
- **Offizielle Quellen:**
  - https://bughunters.google.com/about/rules/open-source/patch-rewards-program-rules
  - https://bughunters.google.com/open-source-security/patch-rewards

### GitHub Bug Bounty

- **Autorisierung:** GitHub publishes scope, rules, rewards and legal safe harbor.
- **Scope:** Listed GitHub domains and products such as CLI, Desktop, Mobile and Enterprise; arbitrary GitHub-owned repositories are not automatically eligible.
- **Einreichung:** GitHub bounty submission path
- **Vergütung:** Published guidance ranges from USD 617 to USD 30,000 or more.
- **Vergütungspfad:** `explicit`
- **Beobachtet:** `2026-08-06T10:38:00Z`
- **Explizit im Scope:**
  - products and domains listed by GitHub's current scope
- **Explizit oder praktisch ausgeschlossen:**
  - unlisted third-party subdomains
  - arbitrary repositories solely because GitHub owns the organization
- **Erlaubte Methoden:**
  - passive review of an explicitly in-scope open-source client
  - local exact-version reproduction after separate approval
- **Ausschlüsse des Piloten:**
  - no social engineering
  - no access to other users' data
  - no external submission in this pilot
- **Offizielle Quellen:**
  - https://bounty.github.com/
  - https://bounty.github.com/scope
  - https://bounty.github.com/rules.html
  - https://bounty.github.com/rewards
  - https://docs.github.com/en/site-policy/security-policies/github-bug-bounty-program-legal-safe-harbor

### Google Open Source Software Vulnerability Rewards Program

- **Autorisierung:** Google authorizes good-faith research and confidential reports for the latest versions of Google OSS.
- **Scope:** Public repositories in Google-owned GitHub organizations, selected external repositories, repository configuration and qualifying dependencies.
- **Einreichung:** Google Bug Hunters form with OSS VRP selected
- **Vergütung:** Rewards are tier- and impact-dependent; OT2 product vulnerabilities have no published financial reward, while qualifying supply-chain issues may be rewarded.
- **Vergütungspfad:** `tier-dependent`
- **Beobachtet:** `2026-08-06T10:38:00Z`
- **Explizit im Scope:**
  - latest Google-owned public repositories
  - selected external repositories
  - repository configuration and qualifying dependencies
- **Explizit oder praktisch ausgeschlossen:**
  - OT3 projects for financial rewards
  - OT2 product vulnerabilities for financial rewards
  - duplicate root causes
- **Erlaubte Methoden:**
  - passive public-source review
  - local pinned-version reproduction after separate approval
- **Ausschlüsse des Piloten:**
  - no production traffic
  - no speculative or unvalidated AI report
  - no external submission in this pilot
- **Offizielle Quellen:**
  - https://bughunters.google.com/open-source-security
  - https://bughunters.google.com/about/rules/open-source/google-open-source-software-vulnerability-reward-program-rules
  - https://bughunters.google.com/blog/ossvrp-rule-updates-2026

## Genau ein lokaler Prüfplan

- **Programm:** `microsoft-oss-bounty`
- **Repository:** https://github.com/microsoft/agent-framework
- **Exakter Commit:** `422160eabec1776137ff33a7b8dada94d509fc56`
- **Zeitbudget:** 4 Stunden
- **Ziel:** Untrusted serialization, checkpoint, tool, plugin and workflow boundaries in Microsoft Agent Framework
- **Erlaubte Analyse:**
  - read public source, tests, dependencies, policy and history locally
  - run existing tests without model, cloud or service credentials
  - use static search and type-aware reasoning
  - write a local regression test only for a concrete code path
- **Abbruchkriterien:**
  - scope or exact commit cannot be verified
  - production traffic, accounts, credentials, paid services or third-party data are required
  - candidate depends on speculative model behavior
  - candidate matches a published out-of-scope scenario
  - time budget expires without local reproducibility
- **Ausgeschlossene Szenarien:**
  - pickle checkpoint injection requiring attacker write access to the trusted checkpoint storage backend
  - samples, tutorials, quickstarts, demos and experimental components
- **Non-Claims:**
  - no vulnerability is asserted
  - no production testing is authorized
  - no account, submission, disclosure or publication is authorized
  - no reward entitlement is established

## Pilotgrenzen

- `public-information-and-public-source-only`
- `no-active-target-traffic`
- `no-account-creation`
- `no-external-submission`
- `no-publication`
- `zero-additional-cost`
- `separate-target-bound-authorization-required-for-external-effect`

Jede externe Wirkung benötigt einen separaten zielgebundenen Auftrag und einen frischen Scope-Readback.
