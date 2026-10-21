from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

def test_active_organization_session_migration_contract() -> None:
    source = (BACKEND / "alembic" / "versions" / "f6b1c2d3e4a5_persist_active_organization_in_sessions.py").read_text()
    assert 'active_organization_id' in source
    assert 'auth_sessions' in source
    assert '"organizations"' in source
    assert '["id"]' in source
    assert 'SET NULL' in source
    assert 'd4a8b61f2e73' in source
