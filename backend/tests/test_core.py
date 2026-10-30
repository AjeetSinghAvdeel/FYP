from app.services.risk_engine import prioritize_tests


def test_prioritize_tests_returns_ranked_candidates():
    findings = [{"severity": "critical"}, {"severity": "high"}]
    candidates = prioritize_tests(findings, "https://example.com")
    assert len(candidates) == 4
    assert candidates[0].score >= candidates[-1].score
