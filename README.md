# Security program metrics

Turn a validated vulnerability CSV into a deterministic backlog, remediation
queue, SLA report, and mean remediation time. The example records are synthetic.
There are no external services or third-party Python dependencies.

Use Python 3.11 or newer.

## Run

```sh
python3 -m unittest -v
python3 metrics.py examples/findings.csv \
  --since 2026-10-01T00:00:00Z \
  --as-of 2026-11-01T00:00:00Z
```

For this fixture, expect 4 open findings, 3 overdue findings, 3 resolutions in the
window, 66.67% resolution SLA compliance, and 200 mean remediation hours.

## Input

| Column | Rule |
| --- | --- |
| `id` | Nonempty and unique |
| `service`, `owner` | Nonempty |
| `severity` | Critical, high, medium, or low; case-insensitive |
| `opened_at` | Timezone-aware ISO timestamp |
| `closed_at` | Empty for unresolved findings, otherwise a timezone-aware timestamp not before opening |
| `internet_exposed`, `exploited` | `true` or `false`; case-insensitive |

All columns are required. Invalid rows, duplicate IDs, missing values, and
unexpected columns produce an error and nonzero exit status. No rows are
silently discarded as malformed.

## Definitions

- **Backlog:** opened by the snapshot time and not closed at or before it.
  A later closure does not change an earlier snapshot.
- **Resolution window:** closures between `since` and `as-of`, inclusive.
- **SLA:** critical 7 days, high 30, medium 90, low 180, measured in elapsed time
  from opening. These are demonstration targets, not universal standards.
- **Overdue:** still open strictly after its deadline. At the exact deadline,
  the finding is not yet overdue.
- **Compliance:** on-time closures divided by all closures in the window.
  No resolutions means `null`, not 0% or 100%.
- **Mean remediation hours:** elapsed opening-to-closure time for resolutions
  in the window. No observations means `null`.
- **Priority:** confirmed exploitation first, then severity, internet exposure,
  oldest opening, and ID as a stable tiebreaker. This is an explicit ordering,
  not a calibrated risk score.

## Interpretation limits

Closure-only metrics exclude unresolved findings and can look better while a
backlog grows. Read them alongside backlog and overdue counts. The example does
not model accepted risk, asset criticality, reopened findings, duplicates across
scanners, or business impact. Add those definitions before using it for a
production reporting program.

Output includes service and owner labels. Use approved inputs and retention
controls; do not put real vulnerability exports in this repository.

## License

[MIT](LICENSE)
