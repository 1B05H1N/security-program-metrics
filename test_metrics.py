from datetime import timedelta
from io import StringIO
import unittest

from metrics import Finding, make_report, parse_timestamp, read_findings


class MetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.opened = parse_timestamp("2026-10-01T00:00:00Z")

    def finding(
        self,
        identifier: str = "F-1",
        severity: str = "critical",
        closed_days: int | None = None,
        exploited: bool = False,
        exposed: bool = False,
    ) -> Finding:
        return Finding(
            identifier, "api", severity, self.opened,
            None if closed_days is None else self.opened + timedelta(days=closed_days),
            exposed, exploited, "platform",
        )

    def test_exact_sla_deadline_is_not_overdue(self) -> None:
        deadline = self.opened + timedelta(days=7)
        self.assertEqual(make_report([self.finding()], self.opened, deadline)["overdue_total"], 0)
        self.assertEqual(
            make_report([self.finding()], self.opened, deadline + timedelta(seconds=1))["overdue_total"],
            1,
        )

    def test_closure_after_snapshot_is_still_in_backlog(self) -> None:
        report = make_report([self.finding(closed_days=12)], self.opened, self.opened + timedelta(days=10))
        self.assertEqual(report["backlog_total"], 1)
        self.assertEqual(report["resolved_in_window"], 0)
        self.assertIsNone(report["sla_compliance_percent"])

    def test_resolution_window_and_sla_denominator(self) -> None:
        findings = [
            self.finding("on-time", closed_days=7),
            self.finding("late", closed_days=10),
            self.finding("still-open"),
        ]
        report = make_report(findings, self.opened + timedelta(days=7), self.opened + timedelta(days=10))
        self.assertEqual(report["resolved_in_window"], 2)
        self.assertEqual(report["resolved_within_sla"], 1)
        self.assertEqual(report["sla_compliance_percent"], 50.0)
        self.assertEqual(report["mean_remediation_hours"], 204.0)

    def test_future_findings_are_excluded_from_historical_snapshot(self) -> None:
        report = make_report([self.finding()], self.opened - timedelta(days=2), self.opened - timedelta(days=1))
        self.assertEqual(report["backlog_total"], 0)
        self.assertEqual(report["future_findings_excluded"], 1)

    def test_exploitation_precedes_severity_then_exposure(self) -> None:
        findings = [
            self.finding("critical"),
            self.finding("exploited-medium", "medium", exploited=True),
            self.finding("exposed-critical", exposed=True),
        ]
        report = make_report(findings, self.opened, self.opened + timedelta(days=1))
        self.assertEqual(
            report["remediation_queue"],
            [
                {
                    "id": finding.id, "service": "api", "owner": "platform",
                    "severity": finding.severity, "exploited": finding.exploited,
                    "internet_exposed": finding.internet_exposed, "days_open": 1,
                    "sla_deadline": finding.deadline.isoformat().replace("+00:00", "Z"),
                    "overdue": False,
                }
                for finding in (findings[1], findings[2], findings[0])
            ],
        )

    def test_invalid_csv_values_fail_explicitly(self) -> None:
        header = "id,service,severity,opened_at,closed_at,internet_exposed,exploited,owner\n"
        for row in (
            "F-1,api,unknown,2026-10-01T00:00:00Z,,true,false,team\n",
            "F-1,api,high,2026-10-01T00:00:00,,true,false,team\n",
            "F-1,api,high,2026-10-01T00:00:00Z,,yes,false,team\n",
            "F-1,api,high,2026-10-01T00:00:00Z,2026-09-01T00:00:00Z,true,false,team\n",
            "F-1,api,high,2026-10-01T00:00:00Z,,true,false\n",
        ):
            with self.subTest(row=row):
                with self.assertRaises(ValueError):
                    read_findings(StringIO(header + row))

    def test_duplicate_ids_are_rejected(self) -> None:
        header = "id,service,severity,opened_at,closed_at,internet_exposed,exploited,owner\n"
        row = "F-1,api,high,2026-10-01T00:00:00Z,,true,false,team\n"
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            read_findings(StringIO(header + row + row))

    def test_reversed_reporting_window_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "since"):
            make_report([], self.opened + timedelta(days=1), self.opened)


if __name__ == "__main__":
    unittest.main()
