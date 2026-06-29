"""Tests for the 3 new playbook patterns added in the final session:
MONITORING_ENHANCED_DETECTION, CREDENTIAL_HARDENING, SERVICE_DISABLE_UNUSED.

Also verifies total pattern count is 11.
"""
from advisoryops.playbook import load_playbook, Playbook


def _pb() -> Playbook:
    return load_playbook()


# ---------- Pattern count ----------

def test_playbook_has_11_patterns():
    pb = _pb()
    assert len(pb.patterns) == 11


# ---------- MONITORING_ENHANCED_DETECTION ----------

def test_monitoring_pattern_exists():
    pb = _pb()
    p = pb.get("MONITORING_ENHANCED_DETECTION")
    assert p is not None


def test_monitoring_pattern_category():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    assert p.category == "monitoring"


def test_monitoring_pattern_has_basis():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    assert "NIST SP 800-82" in p.basis
    assert "CISA" in p.basis


def test_monitoring_pattern_severity_fit_all():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    assert set(p.severity_fit) == {"critical", "high", "medium", "low"}


def test_monitoring_pattern_has_steps():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    assert len(p.steps) >= 3


def test_monitoring_pattern_has_verification():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    assert len(p.verification.evidence) >= 3


def test_monitoring_pattern_has_rollback():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    assert len(p.rollback.steps) >= 2


def test_monitoring_pattern_roles():
    p = _pb().get("MONITORING_ENHANCED_DETECTION")
    roles = {s.role for s in p.steps}
    assert "infosec" in roles
    assert "netops" in roles


# ---------- CREDENTIAL_HARDENING ----------

def test_credential_pattern_exists():
    pb = _pb()
    p = pb.get("CREDENTIAL_HARDENING")
    assert p is not None


def test_credential_pattern_category():
    p = _pb().get("CREDENTIAL_HARDENING")
    assert p.category == "access_control"


def test_credential_pattern_has_basis():
    p = _pb().get("CREDENTIAL_HARDENING")
    assert "NIST SP 800-82" in p.basis
    assert "FDA" in p.basis


def test_credential_pattern_severity_fit():
    p = _pb().get("CREDENTIAL_HARDENING")
    assert "critical" in p.severity_fit
    assert "high" in p.severity_fit
    assert "medium" in p.severity_fit


def test_credential_pattern_has_steps():
    p = _pb().get("CREDENTIAL_HARDENING")
    assert len(p.steps) >= 4


def test_credential_pattern_has_verification():
    p = _pb().get("CREDENTIAL_HARDENING")
    assert len(p.verification.evidence) >= 3


def test_credential_pattern_roles():
    p = _pb().get("CREDENTIAL_HARDENING")
    roles = {s.role for s in p.steps}
    assert "infosec" in roles
    assert "htm_ce" in roles


# ---------- SERVICE_DISABLE_UNUSED ----------

def test_service_disable_pattern_exists():
    pb = _pb()
    p = pb.get("SERVICE_DISABLE_UNUSED")
    assert p is not None


def test_service_disable_pattern_category():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    assert p.category == "hardening"


def test_service_disable_pattern_has_basis():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    assert "IEC 62443" in p.basis
    assert "CISA" in p.basis


def test_service_disable_pattern_severity_fit():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    assert "critical" in p.severity_fit
    assert "high" in p.severity_fit
    assert "medium" in p.severity_fit


def test_service_disable_pattern_has_steps():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    assert len(p.steps) >= 3


def test_service_disable_pattern_has_verification():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    assert len(p.verification.evidence) >= 3


def test_service_disable_pattern_roles():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    roles = {s.role for s in p.steps}
    assert "infosec" in roles
    assert "htm_ce" in roles


def test_service_disable_pattern_has_safety_notes():
    p = _pb().get("SERVICE_DISABLE_UNUSED")
    assert len(p.safety_notes) >= 3
