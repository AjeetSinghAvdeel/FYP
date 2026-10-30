from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models import AuditEvent
from app.services.audit import record_event, verify_chain
from app.services.attack_graph import AttackGraphEngine
from app.services.evaluation import calculate_metrics
from app.services.policy import PolicyEngine
from app.services.risk_engine import calculate_priority, prioritize_tests
from app.services.tool_adapters import FFUFAdapter, GobusterAdapter, NiktoAdapter, NmapAdapter
from app.services.validation import EvidenceValidator


def test_empty_web_assessment_starts_with_reconnaissance():
    assert prioritize_tests([], "http://127.0.0.1:3000")[0].tool == "nmap"


def test_priority_penalty_is_deterministic():
    score, contributions = calculate_priority({"severity": 1, "information_gain": 1, "execution_cost": 1, "uncertainty": 1})
    assert score == 20.0
    assert contributions["execution_cost"] == 5.0
    assert contributions["uncertainty"] == 10.0


def test_policy_rejects_public_targets_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
    assert PolicyEngine.target_is_allowed("http://127.0.0.1:8000")[0]
    assert not PolicyEngine.target_is_allowed("https://example.com")[0]


def test_adapter_rejects_command_arguments_and_supports_mock(monkeypatch):
    monkeypatch.setenv("PENTEST_EXECUTION_MODE", "mock")
    adapter = NmapAdapter()
    assert adapter.execute("http://127.0.0.1:3000", ["-sV"])["mode"] == "mock"
    assert adapter.execute("http://127.0.0.1:3000", ["--exec", "id"])["status"] == "invalid"
    assert adapter.execute("https://example.com")["status"] == "blocked"


def test_nmap_builds_host_port_command_and_parses_service_xml():
    adapter = NmapAdapter()
    command = adapter.build_command("http://127.0.0.1:3000", [])
    assert command[-1] == "127.0.0.1"
    assert command[command.index("-p") + 1] == "3000"
    assert "http://" not in command[-1]
    assert adapter.request_budget() == 1
    parsed = adapter.parse_output('<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="3000"><state state="open"/><service name="ppp" servicefp="HTTP/1.1 200 OK"/></port></ports></host></nmaprun>')
    assert parsed == [{"type": "service", "address": "127.0.0.1", "port": 3000, "protocol": "tcp", "state": "open", "name": "http", "product": None, "version": None}]


def test_enumeration_is_bounded_and_discovery_is_not_confirmed():
    assert "-rate" in FFUFAdapter().build_command("http://127.0.0.1:3000", [])
    gobuster = GobusterAdapter().build_command("http://127.0.0.1:3000", [])
    assert gobuster[gobuster.index("-w") + 1].endswith("wordlist.txt")
    result = EvidenceValidator.evaluate({"status": "ok", "output": "port 3000 open", "observations": [{"type": "service"}]}, "http://127.0.0.1:3000")
    assert result["status"] == "candidate"
    assert NiktoAdapter().request_budget() == 250


def test_audit_chain_detects_tampering():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    record_event(session, "first", outcome="ok")
    record_event(session, "second", outcome="ok")
    session.commit()
    assert verify_chain(session)["valid"]
    session.query(AuditEvent).first().outcome = "modified"
    session.commit()
    assert not verify_chain(session)["valid"]


def test_evaluation_metrics_use_ground_truth():
    metrics = calculate_metrics(
        {"vulnerabilities": ["v1", "v2"], "attack_paths": ["p1"]},
        {
            "vulnerabilities": ["v1", "false"],
            "confirmed_vulnerabilities": ["v1"],
            "candidate_vulnerabilities": ["v1", "false"],
            "attack_paths": ["p1"],
            "tool_actions": 2,
            "elapsed_seconds": 10,
            "selected_actions": ["nmap"],
            "risk_rank": ["nmap"],
        },
    )
    assert metrics["vulnerability_coverage"]["value"] == 0.5
    assert metrics["attack_path_coverage"]["value"] == 1.0
    assert metrics["false_positive_rate"]["value"] == 0.5
    assert metrics["exploit_validation_rate"]["value"] == 0.5


def test_attack_graph_does_not_invent_exploit_paths():
    graph = AttackGraphEngine.build_snapshot([
        {"asset": "http://127.0.0.1:3000", "source_tool": "nmap", "title": "HTTP service", "severity": "low", "status": "candidate", "observations": [{"type": "service", "port": 3000, "protocol": "tcp", "name": "http", "state": "open"}]},
        {"asset": "http://127.0.0.1:3000", "source_tool": "ffuf", "title": "Path evidence", "severity": "low", "status": "candidate", "observations": [{"type": "path", "url": "http://127.0.0.1:3000/robots.txt"}]},
    ])
    assert len([node for node in graph["nodes"] if node["data"]["kind"] == "target"]) == 1
    assert all("exploit path" not in edge["label"] for edge in graph["edges"])
    assert {edge["label"] for edge in graph["edges"]} == {"observed on", "evidence from"}
