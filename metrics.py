"""Deterministic vulnerability backlog and remediation reporting."""

import argparse
import csv
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from statistics import mean
from typing import TextIO


SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
SEVERITY_ORDER = {severity: index for index, severity in enumerate(SLA_DAYS)}
COLUMNS = (
    "id", "service", "severity", "opened_at", "closed_at",
    "internet_exposed", "exploited", "owner",
)


@dataclass(frozen=True)
class Finding:
    id: str
    service: str
    severity: str
    opened_at: datetime
    closed_at: datetime | None
    internet_exposed: bool
    exploited: bool
    owner: str

    @property
    def deadline(self) -> datetime:
        return self.opened_at + timedelta(days=SLA_DAYS[self.severity])


def parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"Invalid timestamp: {value!r}") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"Timestamp needs a timezone: {value!r}")
    return timestamp.astimezone(UTC)


def parse_flag(value: str, field: str) -> bool:
    normalized = value.casefold()
    if normalized not in {"true", "false"}:
        raise ValueError(f"{field} must be true or false")
    return normalized == "true"


def read_findings(stream: TextIO) -> list[Finding]:
    reader = csv.DictReader(stream)
    if reader.fieldnames is None or sorted(reader.fieldnames) != sorted(COLUMNS):
        raise ValueError("CSV headers must contain each documented column exactly once")
    findings: list[Finding] = []
    seen: set[str] = set()
    for line, row in enumerate(reader, start=2):
        if set(row) != set(COLUMNS) or any(value is None for value in row.values()):
            raise ValueError(f"Line {line}: incorrect number of CSV values")
        values = {key: value.strip() for key, value in row.items()}
        try:
            for field in ("id", "service", "severity", "opened_at", "owner"):
                if not values[field]:
                    raise ValueError(f"{field} must not be empty")
            identifier = values["id"]
            if identifier in seen:
                raise ValueError(f"Duplicate finding ID: {identifier}")
            severity = values["severity"].casefold()
            if severity not in SLA_DAYS:
                raise ValueError(f"Unsupported severity: {severity}")
            opened = parse_timestamp(values["opened_at"])
            closed = parse_timestamp(values["closed_at"]) if values["closed_at"] else None
            if closed is not None and closed < opened:
                raise ValueError("closed_at cannot precede opened_at")
            finding = Finding(
                identifier, values["service"], severity, opened, closed,
                parse_flag(values["internet_exposed"], "internet_exposed"),
                parse_flag(values["exploited"], "exploited"), values["owner"],
            )
        except ValueError as error:
            raise ValueError(f"Line {line}: {error}") from error
        seen.add(identifier)
        findings.append(finding)
    return findings


def timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def make_report(findings: list[Finding], since: datetime, as_of: datetime) -> dict[str, object]:
    if since.tzinfo is None or as_of.tzinfo is None:
        raise ValueError("Reporting boundaries need timezones")
    if since > as_of:
        raise ValueError("since cannot be later than as_of")
    observed = [finding for finding in findings if finding.opened_at <= as_of]
    active = [
        finding for finding in observed
        if finding.closed_at is None or finding.closed_at > as_of
    ]
    resolved = [
        finding for finding in observed
        if finding.closed_at is not None and since <= finding.closed_at <= as_of
    ]
    ordered = sorted(
        active,
        key=lambda finding: (
            not finding.exploited,
            SEVERITY_ORDER[finding.severity],
            not finding.internet_exposed,
            finding.opened_at,
            finding.id,
        ),
    )
    queue = [
        {
            "id": finding.id,
            "service": finding.service,
            "owner": finding.owner,
            "severity": finding.severity,
            "exploited": finding.exploited,
            "internet_exposed": finding.internet_exposed,
            "days_open": (as_of - finding.opened_at).days,
            "sla_deadline": timestamp_text(finding.deadline),
            "overdue": as_of > finding.deadline,
        }
        for finding in ordered
    ]
    within_sla = sum(
        1 for finding in resolved
        if finding.closed_at is not None and finding.closed_at <= finding.deadline
    )
    hours = [
        (finding.closed_at - finding.opened_at).total_seconds() / 3600
        for finding in resolved if finding.closed_at is not None
    ]
    return {
        "window": {"since": timestamp_text(since), "as_of": timestamp_text(as_of)},
        "findings_observed": len(observed),
        "future_findings_excluded": len(findings) - len(observed),
        "backlog_total": len(active),
        "backlog_by_severity": {
            severity: sum(finding.severity == severity for finding in active)
            for severity in SLA_DAYS
        },
        "overdue_total": sum(as_of > finding.deadline for finding in active),
        "resolved_in_window": len(resolved),
        "resolved_within_sla": within_sla,
        "sla_compliance_percent": round(100 * within_sla / len(resolved), 2) if resolved else None,
        "mean_remediation_hours": round(mean(hours), 2) if hours else None,
        "remediation_queue": queue,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--since", required=True, help="Timezone-aware ISO timestamp")
    parser.add_argument("--as-of", required=True, help="Timezone-aware ISO timestamp")
    arguments = parser.parse_args()
    try:
        since = parse_timestamp(arguments.since)
        as_of = parse_timestamp(arguments.as_of)
        with arguments.csv.open(newline="", encoding="utf-8") as stream:
            findings = read_findings(stream)
        report = make_report(findings, since, as_of)
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
