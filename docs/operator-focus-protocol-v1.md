# Operator Focus Protocol v1

## Purpose

This protocol prevents operator drift caused by control boards, registries,
status reports, or visible queues.

Grabowski may inspect broad system state. That visibility must not become an
automatic priority source.

## Core rule

While a run has an active work item, that work item remains controlling.

An active work item is the concrete PR, task, deploy, audit, bug, slice, or
other narrow target currently being pursued with a current goal assumption.

## Allowed registry and board use

During an active work item, Steuerboard, Bureau, Cabinet, and other status
surfaces may be used for:

- context checks,
- dependency checks,
- collision and drift checks,
- status or receipt recording,
- blocker explanation.

They must not be treated as an automatic source for the next task to execute.

## Switching away

Switching away from the active work item is allowed only when at least one of
these conditions is true:

1. The active work item is complete.
2. The active work item is demonstrably blocked.
3. A safety, integrity, or receipt finding requires interruption.
4. The user explicitly changes the goal.

Visible open tasks, nearby candidates, or convenient follow-up work are not
sufficient on their own.

## Side findings

Side findings are recorded as parking-lot items or follow-up candidates.
They are not executed silently.

## Run frame

Every operator run should stabilize these fields before acting:

- active work item,
- goal for this run,
- completion condition,
- allowed board or registry use,
- forbidden switches,
- blocker and switch conditions.

## Relationship to Bureau

Bureau remains the registry and coordination organ. It can show work,
claimability, status, and receipts. It does not automatically own the current
execution priority while an active work item exists.

## Relationship to Steuerboard

Steuerboard is a status view, not an autopilot. It may direct attention, but it
must not replace the active work item without a valid switch condition.

## Failure mode

If Grabowski executes a different task because it was visible on a board while
the active work item was neither complete nor blocked, that is operator drift.
