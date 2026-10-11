# 1. The robot scan UI runs locally, on the user's machine

- **Status:** accepted (provisional - revisit after the beta, see "Revisit when")
- **Date:** 2026-10-04
- **Epic:** Robot Scan UI (spec in the project vault: *Robot Scan UI - Spec*)

## Context

The robot scan UI lets a user add a robot they own, see it as a diagram with
each weakness pinned to the part it's in, and recheck a finding after fixing
it. Scans have to reach the robot, which sits on a lab or office network.

Two ways to run it:

- **A. Local web UI.** `glitched ui` serves the app on `127.0.0.1`, using the
  same database, checks and safety rules as the CLI.
- **B. Hosted app plus a local runner.** A web app on the internet; a small
  runner on the robot's network pairs with it and runs scans.

A hosted page can't - and shouldn't - reach into a private network, so B needs
the runner anyway. B also needs accounts, hosting, a secure runner link, and
moves device names, addresses and results off the user's network.

## Decision

Build **A** first.

- Nothing about the user's robots leaves their machine; no accounts.
- It reuses everything that exists: the database, `glitched.safety`, the
  passive checks, exposure matching, Docker Compose.
- Design the API between the UI and the scanner **as if it were remote**
  (JSON over HTTP, scans as jobs with progress events), so B is an addition
  later, not a rewrite.

## Consequences

- One machine at a time; no sharing between team members until B.
- The UI is a local web server, which other web pages in the user's browser
  could try to call. It must:
  - bind to `127.0.0.1` only, never `0.0.0.0`;
  - check the `Host` header is `127.0.0.1:<port>` or `localhost:<port>`
    (blocks DNS rebinding);
  - require a random token created at start-up (printed in the URL that
    `glitched ui` opens, then kept in a cookie) on every API call, so no other
    site can start a scan.
- Every action stays available from the CLI. The CLI remains the way to script
  Glitched and run it in CI.

## Findings model

The existing `findings` table belongs to one assessment (one scan run). The UI
needs one list per robot that persists across scans and has its own lifecycle,
so a robot's findings are a new table, kept in sync from what Glitched already
knows. (Schema changes are added in place, as always.)

`device_findings` - one row per robot × source × reference:

| Column | Meaning |
|---|---|
| `device_id` | the robot (`devices`) |
| `kind` | how we know: `observed` (a check saw it), `declared` (the user's answers), `known_vulnerability` (CVE matched by platform or component+version), `possible` (EMB3D threat that fits but wasn't tested) |
| `source`, `ref_id` | where it comes from: `check`/`TID-406`, `profile`/`PID-15`, `cve`/`CVE-…`, `emb3d`/`TID-…` |
| `part` | diagram anchor: `network`, `cloud_link`, `main_controller`, `debug_port`, `peripherals`, `whole_robot` |
| `title`, `detail`, `evidence` | plain-language finding, its latest detail, the latest evidence text |
| `status` | `open`, `fix_applied`, `resolved`, `accepted_risk`, `not_applicable` |
| `status_note`, `accepted_until` | why (required for accepted risk) and until when |
| `first_seen_at`, `last_seen_at`, `resolved_at`, `last_assessment_id` | history pointers |

`device_finding_events` - every status change: when, from, to, by whom (`scan`,
`recheck`, `sync`, `user`), note.

**Sync rules** (after each scan, and whenever a robot's profile or the threat
intel changes):

- A finding that is present and has no row → new row, `open`.
- Present again after `resolved` → `open` ("reappeared").
- Still present after `fix_applied` → `open` ("still present").
- An observed finding whose check now says not present → `resolved` (by scan).
  Declared, known-vulnerability and possible findings that no longer match the
  profile (answer changed, SBOM version updated) → `resolved` (by sync).
- Inconclusive check results change nothing but the evidence.
- `accepted_risk` and `not_applicable` are the user's call and are never
  changed by a scan - except that an accepted risk past `accepted_until`
  returns to `open`.

## API outline

All JSON, under `/api`, token required. Long operations return a job id;
progress streams from `/api/jobs/{id}/events` (server-sent events).

| Method and path | Does |
|---|---|
| `GET /api/robots` | robots with open-finding counts and last scan time |
| `POST /api/robots` | add a robot: name, host, type, authorization (safety rules apply) |
| `GET /api/robots/{id}` | robot, profile, diagram parts, threat-intel freshness |
| `PUT /api/robots/{id}/profile` | questionnaire answers or a `glitch.yaml` |
| `POST /api/robots/{id}/sbom` | upload a CycloneDX/SPDX SBOM |
| `GET /api/robots/{id}/scan-plan` | exactly what a scan will send, before running it |
| `POST /api/robots/{id}/scans` | start a scan → job |
| `GET /api/robots/{id}/findings` | the robot's findings, ranked |
| `PATCH /api/findings/{id}` | set status: `fix_applied`, `accepted_risk` (note + until), `not_applicable`, `open` |
| `POST /api/findings/{id}/recheck` | re-run only the check behind an observed finding → job |
| `GET /api/jobs/{id}/events` | progress events; `DELETE /api/jobs/{id}` cancels |

## Revisit when

Beta testers say they need to share results with a team or manage a fleet from
one place - that's option B, as its own epic.
