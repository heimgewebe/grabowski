# Autorisierter Bounty-Katalog v1

Beobachtet: `2026-08-06T09:49:58Z`

Der Pilot ist rein passiv: kein Zielsystemverkehr, kein Account, keine Meldung und keine Veröffentlichung.

## Revisionsbindung

- `catalog_sha256`: `3748e9100091e353c636b5897a9436e8ea6e3532d5a3128aab6469284cb6d3c2`
- `ranking_sha256`: `6ab16336f282acb1e1a94a4a0e2996a4cf5ef1ee31172ee02ae926d32073cbda`
- `local_review_plan_sha256`: `c633fd21b96d87805e84d55b330625dbcbb803ed84bc2f3a3b5bc82057515cb1`
- `bundle_sha256`: `d85ef08fac70854cc78adbb943b0f5799ca822eacaf1139611c8a6c21f594167`

## Rangliste

| Rang | Programm | Punkte | Schwerpunkt |
|---:|---|---:|---|
| 1 | Google Open Source Software Vulnerability Rewards Program | 84 | Google-owned open-source repositories, including AI-agent projects |
| 2 | GitLab Bug Bounty Program | 80 | Public GitLab product source and GitLab.com |
| 3 | Mozilla Client Security Bug Bounty | 76 | Current Firefox desktop and mobile clients |
| 4 | GitHub Bug Bounty | 72 | GitHub services and explicitly listed products, including selected open-source clients |
| 5 | OpenAI Security Bug Bounty | 60 | OpenAI security issues under the current Bugcrowd program |

## Programme

### Google Open Source Software Vulnerability Rewards Program

- **Autorisierung:** Official OSS VRP rules authorize good-faith research and confidential reporting.
- **Scope:** Latest public Google-owned repositories, selected repositories, configuration and qualifying dependencies.
- **Einreichung:** Google Bug Hunters form with OSS VRP selected
- **Vergütung:** Published ranges reach USD 31,337 for flagship supply-chain compromises; current tables govern other classes.
- **Beobachtet:** `2026-08-06T09:49:58Z`
- **Erlaubte Methoden:**
  - passive public-source review
  - local pinned-version reproduction after separate approval
- **Ausschlüsse:**
  - no production traffic
  - no unvalidated AI report
  - no duplicate root cause
- **Offizielle Quellen:**
  - https://bughunters.google.com/open-source-security
  - https://bughunters.google.com/about/rules/open-source/google-open-source-software-vulnerability-reward-program-rules
  - https://bughunters.google.com/blog/ossvrp-rule-updates-2026

### GitLab Bug Bounty Program

- **Autorisierung:** GitLab directs researchers to its official HackerOne scope and rules.
- **Scope:** Qualifying GitLab product or GitLab.com issues; hosted third-party projects are not implicitly authorized.
- **Einreichung:** GitLab HackerOne; confidential issue only as documented fallback
- **Vergütung:** Current HackerOne severity table governs rewards; the fallback route is not a compensation path.
- **Beobachtet:** `2026-08-06T09:49:58Z`
- **Erlaubte Methoden:**
  - passive source review
  - local exact-version tests after separate approval
- **Ausschlüsse:**
  - no third-party project testing
  - no denial of service
  - no public disclosure
- **Offizielle Quellen:**
  - https://about.gitlab.com/security/disclosure/
  - https://hackerone.com/gitlab

### Mozilla Client Security Bug Bounty

- **Autorisierung:** Mozilla publishes eligibility, safe-harbor and confidential-reporting rules.
- **Scope:** Current official Firefox, Firefox for Android and Firefox for iOS versions.
- **Einreichung:** Mozilla confidential security-bug reporting process
- **Vergütung:** Published client rewards range from USD 3,000 to USD 20,000 for qualifying high or critical findings.
- **Beobachtet:** `2026-08-06T09:49:58Z`
- **Erlaubte Methoden:**
  - passive Mozilla-source review
  - local proof against an official build after separate approval
- **Ausschlüsse:**
  - no end-of-life target
  - no unsupported build as sole reproducer
  - no premature disclosure
- **Offizielle Quellen:**
  - https://www.mozilla.org/en-US/security/client-bug-bounty/
  - https://www.mozilla.org/en-US/security/bug-bounty/
  - https://www.mozilla.org/en-US/security/bug-bounty/faq/

### GitHub Bug Bounty

- **Autorisierung:** GitHub publishes scope, rules, rewards and legal safe harbor.
- **Scope:** Listed domains and products such as CLI, Desktop, Mobile and Enterprise; arbitrary GitHub-owned repositories are not automatically eligible.
- **Einreichung:** GitHub bounty submission path linked from bounty.github.com
- **Vergütung:** Published guidance ranges from USD 617 to USD 30,000 or more.
- **Beobachtet:** `2026-08-06T09:49:58Z`
- **Erlaubte Methoden:**
  - passive in-scope client-source review
  - local exact-version reproduction after separate approval
- **Ausschlüsse:**
  - no third-party subdomain
  - no social engineering
  - no access to others' data
- **Offizielle Quellen:**
  - https://bounty.github.com/
  - https://bounty.github.com/scope
  - https://bounty.github.com/rules.html
  - https://bounty.github.com/rewards
  - https://docs.github.com/en/site-policy/security-policies/github-bug-bounty-program-legal-safe-harbor

### OpenAI Security Bug Bounty

- **Autorisierung:** OpenAI's disclosure policy invites qualifying reports through Bugcrowd.
- **Scope:** Systems in the current Bugcrowd rules; generic jailbreak and safety-abuse reports use different programs.
- **Einreichung:** OpenAI Bugcrowd program linked by the official policy
- **Vergütung:** OpenAI announced rewards up to USD 100,000 for exceptional and differentiated critical findings; current program rules govern other tiers.
- **Beobachtet:** `2026-08-06T09:49:58Z`
- **Erlaubte Methoden:**
  - passive public-artifact review
  - local exact-artifact analysis after separate approval
- **Ausschlüsse:**
  - no account creation
  - no live-service testing
  - no report without separate authorization
- **Offizielle Quellen:**
  - https://openai.com/index/security-on-the-path-to-agi/
  - https://openai.com/policies/coordinated-vulnerability-disclosure-policy/
  - https://bugcrowd.com/openai

## Genau ein lokaler Prüfplan

- **Programm:** `google-oss-vrp`
- **Repository:** https://github.com/google/adk-python
- **Exakter Commit:** `6ccb83734ed22e79737406a54a9a205f3feed0ab`
- **Zeitbudget:** 6 Stunden
- **Ziel:** Agent tool, plugin, session and serialization trust boundaries in Google ADK Python
- **Erlaubte Analyse:**
  - read public source, tests, dependencies, policy and history locally
  - run existing tests without model or cloud credentials
  - use static search and type-aware reasoning
  - write a local regression test only for a concrete code path
- **Abbruchkriterien:**
  - scope or commit cannot be verified
  - production traffic, credentials, paid services or third-party data are required
  - candidate depends on speculative model behavior
  - budget expires without local reproducibility
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
