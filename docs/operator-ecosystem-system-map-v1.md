# Operator Ecosystem System Map v1

## Purpose

`grabowski_status(view="standard"|"evidence")` exposes a bounded component map under
`system_overview.component_map`.

The map explains the operator ecosystem without creating another lifecycle, task,
health, or deployment truth. It projects already-read authoritative sources and
marks components that require an exact target binding instead of guessing their
state globally.

## Signals

- `green`: the source was observed and its bounded health checks pass.
- `amber`: the source was observed and actionable attention exists, but no
  integrity failure was established.
- `red`: an observed integrity or health failure exists.
- `unknown`: a source required for the global projection was unavailable or
  incomplete.
- `target_required`: the component can only be judged for an exact target.

The overall signal uses the order `red > unknown > amber > target_required > green`.
It is a navigation signal, not mutation authority.

## Components observed globally

- Grabowski runtime and deployment integrity
- connector snapshot binding
- durable task store and projections
- resource leases
- operator obligations
- coding-agent catalog

## Components requiring target binding

- Bureau: task or obligation identity
- GitHub CI: repository and pull request
- RepoGround: repository and bundle stem
- Chronik: operation or receipt identity
- Systemkatalog: system identity

## Contract boundaries

The projection does not establish:

- a second lifecycle truth;
- target-specific health for externally authoritative components;
- correctness of task output;
- permission to mutate;
- future execution authority.

Consumers must retain each component's `authority`, `observed`, `required_binding`,
and `evidence` fields. They must not convert `target_required` into green or red
without performing the named target-bound read.
