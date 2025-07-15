"""
Advanced report generation utilities
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import asdict


class ReportGenerator:
    """Advanced report generator with multiple formats and templates"""

    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)

    def generate_executive_summary(self, scan_result) -> Dict[str, Any]:
        """Generate executive summary for management"""

        threats_by_severity = {}
        for threat in scan_result.threats_found:
            severity = threat.severity
            if severity not in threats_by_severity:
                threats_by_severity[severity] = []
            threats_by_severity[severity].append(threat)

        risk_score = self._calculate_risk_score(scan_result.threats_found)

        return {
            "executive_summary": {
                "scan_date": datetime.now().strftime("%Y-%m-%d"),
                "target_system": scan_result.target_url,
                "overall_risk_score": risk_score,
                "total_vulnerabilities": len(scan_result.threats_found),
                "critical_issues": len(threats_by_severity.get("critical", [])),
                "high_issues": len(threats_by_severity.get("high", [])),
                "recommendations_count": len(scan_result.recommendations),
                "business_impact": self._assess_business_impact(scan_result.threats_found)
            }
        }

    def _calculate_risk_score(self, threats: List) -> float:
        """Calculate overall risk score (0-100)"""
        if not threats:
            return 0.0

        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }

        total_score = sum(severity_weights.get(threat.severity, 0) for threat in threats)
        max_possible = len(threats) * 10

        return min((total_score / max_possible) * 100, 100) if max_possible > 0 else 0

    def _assess_business_impact(self, threats: List) -> str:
        """Assess business impact based on threat types"""
        categories = set(threat.category for threat in threats)
        critical_count = sum(1 for threat in threats if threat.severity == "critical")

        if critical_count > 0:
            return "HIGH - Immediate action required"
        elif "data_leakage" in categories:
            return "MEDIUM-HIGH - Data protection concerns"
        elif len(threats) > 5:
            return "MEDIUM - Multiple security issues identified"
        else:
            return "LOW-MEDIUM - Minor security improvements needed"

    def generate_compliance_report(self, scan_result, framework="NIST") -> Dict[str, Any]:
        """Generate compliance-focused report"""

        compliance_mapping = {
            "NIST": {
                "prompt_injection": "ID.RA-1: Asset vulnerabilities are identified",
                "data_leakage": "PR.DS-1: Data-at-rest is protected",
                "function_abuse": "PR.AC-1: Identities and credentials are managed",
                "context_manipulation": "DE.CM-1: Networks are monitored"
            }
        }

        findings = []
        for threat in scan_result.threats_found:
            category = threat.category
            control = compliance_mapping.get(framework, {}).get(category, "General security control")

            findings.append({
                "control_id": control,
                "finding": threat.description,
                "severity": threat.severity,
                "evidence": threat.payload,
                "remediation": threat.mitigation
            })

        return {
            "compliance_report": {
                "framework": framework,
                "assessment_date": datetime.now().isoformat(),
                "findings": findings,
                "compliance_score": max(0, 100 - len(findings) * 10)
            }
        }

    def export_to_csv(self, scan_result, filename: str = None) -> str:
        """Export results to CSV format"""
        import csv

        if filename is None:
            filename = f"{scan_result.scan_id}_export.csv"

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'threat_id', 'category', 'severity', 'confidence',
                'description', 'payload', 'response', 'mitigation', 'timestamp'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for threat in scan_result.threats_found:
                writer.writerow(asdict(threat))

        return filename
