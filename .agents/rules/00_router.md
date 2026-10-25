---
trigger: always_on
---

# Pipeline Router & Global Guardrails
# Scope: applies to every agent, every session

## Global Guardrails
1. Never read, print, log, or commit the contents of `.env` files, key files, tokens, or credentials. If a task needs a secret, reference it by variable name only.
2. Never push to `main`/`master`. Never force-push. Work only on `feature/` or `bugfix/` branches.
3. Stay inside your role's write scope. Exactly one agent writes each artifact (see table below).
4. If you are blocked or the plan is infeasible, set `state` to `blocked` in the status file with a reason, then stop. Do not work around the problem.

## Pipeline
`PM -> Planner -> [Chaos Monkey, only if high_risk] -> user approval -> Builder <-> Validator (per micro-task) -> Release Wrangler`

## State File: `/.plans/<feature>.status.json`
This is the only handoff channel between agents. Read it before acting; update only the fields you own.

```json
{
  "feature": "feature-name",
  "state": "prd_drafted",
  "high_risk": false,
  "gate_mode": "human_per_task",
  "validation_mode": "host",
  "review_rounds": 0,
  "tasks_total": 0,
  "tasks_done": 0,
  "current_task": null,
  "validator_token": { "result": null, "task": null, "timestamp": null },
  "blocked": { "by": null, "reason": null }
}
```

Allowed `state` values, in order:
`prd_drafted -> prd_approved -> planned -> hardened -> approved -> building -> validated -> shipped` (plus `blocked`).

| Artifact / field | Sole writer |
|---|---|
| `/.plans/prd.md`, state `prd_drafted` | PM |
| `state: prd_approved` | User (via PM, only after the user types "PRD approved") |
| `/.plans/<feature>.md`, state `planned`, `high_risk` | Planner |
| `/.plans/<feature>.review.md`, `## Failure Modes & Mitigation` section, state `hardened` | Chaos Monkey |
| `state: approved`, `gate_mode` | User (via Planner, only after the user types "Approved") |
| source code, `current_task`, `tasks_done`, state `building` | Builder |
| `validator_token`, `/.qa/` reports, state `validated` | Validator |
| `validation_mode` | User (default `host`; user or Planner may set `docker` if the feature needs it) |
| branch, commits, PR text, state `shipped` | Release Wrangler |

`validation_mode` values: `host` (default, no Docker) or `docker` (container required, opt-in).

`gate_mode` values: `human_per_task` (default: Builder halts for user approval of each diff) or `validator` (Builder proceeds when the Validator passes; user reviews at PR).
