from __future__ import annotations

import io
from typing import Any


def build_report(assessment: Any, findings: list[Any], executions: list[Any], audit_events: list[Any]) -> dict[str, Any]:
    simulated = any(item.mode == "mock" for item in executions)
    return {
        "id": assessment.id,
        "name": assessment.name,
        "status": assessment.status,
        "target": {
            "name": assessment.target.name,
            "url": assessment.target.target_url,
            "scope": assessment.target.scope,
            "allowed_tools": assessment.target.allowed_tools,
        },
        "summary": assessment.summary,
        "execution_mode": "simulated" if simulated else "real",
        "risk_score": assessment.risk_score,
        "budget": {"limit": assessment.budget, "used": assessment.requests_used, "utilization": round(assessment.requests_used / max(assessment.budget, 1), 3)},
        "findings": [
            {
                "id": item.id,
                "source_tool": item.source_tool,
                "title": item.title,
                "severity": item.severity,
                "confidence": item.confidence,
                "asset": item.asset,
                "vector": item.vector,
                "evidence": item.evidence,
                "status": item.status,
                "risk_score": item.risk_score,
                "risk_breakdown": item.risk_breakdown or {},
                "observations": item.observations or [],
                "simulated": item.simulated,
            }
            for item in findings
        ],
        "executions": [
            {"id": item.id, "tool": item.tool, "status": item.status, "mode": item.mode, "target": item.target, "duration_ms": item.duration_ms, "request_budget": item.request_budget, "requests_made": item.requests_made, "started_at": item.started_at.isoformat(), "finished_at": item.finished_at.isoformat() if item.finished_at else None, "return_code": item.return_code, "stdout": item.output, "stderr": item.stderr, "observations": item.observations or []}
            for item in executions
        ],
        "timeline": [
            {"id": item.id, "event_type": item.event_type, "action": item.action, "decision": item.decision, "outcome": item.outcome, "created_at": item.created_at.isoformat()}
            for item in audit_events
        ],
        "attack_graph": assessment.graph_snapshot or {"nodes": [], "edges": []},
        "limitations": ["Mock execution is simulated and must not be presented as proof of a real vulnerability.", "The prototype performs non-destructive checks only."],
    }


def render_pdf(report: dict[str, Any]) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.lib import colors

    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=0.6 * inch, leftMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    story = [Paragraph("Risk-Guided Assessment Report", styles["Title"]), Paragraph(report["name"], styles["Heading2"]), Spacer(1, 12)]
    story.append(Paragraph(f"Status: {report['status']} | Execution mode: {report['execution_mode']} | Risk score: {report['risk_score']}", styles["BodyText"]))
    story.append(Paragraph(f"Target: {report['target']['name']} ({report['target']['url']})", styles["BodyText"]))
    story.append(Paragraph(f"Authorized scope: {report['target']['scope']} | Tools: {report['target']['allowed_tools']}", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Findings", styles["Heading2"]))
    rows = [["Title", "Severity", "Status", "Confidence", "Simulated"]]
    rows.extend([[item["title"], item["severity"], item["status"], str(item["confidence"]), str(item["simulated"])] for item in report["findings"]])
    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#183b56")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Execution timeline", styles["Heading2"]))
    for event in report["timeline"]:
        story.append(Paragraph(f"{event['created_at']} - {event['event_type']}: {event['outcome'] or ''}", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Limitations", styles["Heading2"]))
    for limitation in report["limitations"]:
        story.append(Paragraph(f"- {limitation}", styles["BodyText"]))
    document.build(story)
    return output.getvalue()