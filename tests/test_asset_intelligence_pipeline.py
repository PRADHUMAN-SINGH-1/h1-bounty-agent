from pathlib import Path

from h1_agent.asset_intelligence import analyze_asset
from h1_agent.models import ScopeAsset


def test_source_code_asset_without_public_artifact_is_manual():
    asset = ScopeAsset(
        id="1",
        asset_type="SOURCE_CODE",
        asset_identifier="private/source-repository",
        eligible_for_bounty=True,
        eligible_for_submission=True,
    )
    result = analyze_asset(asset, type("S", (), {"user_agent": "test"})())
    assert result.status == "manual"
    assert result.evidence


def test_cloud_asset_literal_policy_is_analyzed():
    asset = ScopeAsset(
        id="2",
        asset_type="CLOUD",
        asset_identifier='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}',
        eligible_for_bounty=True,
        eligible_for_submission=True,
    )
    result = analyze_asset(asset, type("S", (), {"user_agent": "test"})())
    assert result.status in {"review", "observed"}
    assert result.evidence


def test_render_contains_optional_two_account_headers():
    text = Path("render.yaml").read_text(encoding="utf-8")
    assert "AUTHZ_HEADER_A" in text
    assert "AUTHZ_HEADER_B" in text
    assert 'key: AUTHZ_MAX_ENDPOINTS' in text


def test_api_uses_store_for_findings():
    text = Path("api/index.py").read_text(encoding="utf-8")
    start = text.index('@app.get("/api/findings")')
    end = text.index('@app.get("/api/capabilities")')
    block = text[start:end]
    assert "Store(Settings())" in block
    assert "_read_state()" not in block


def test_worker_routes_non_web_scoped_assets():
    text = Path("src/h1_agent/worker.py").read_text(encoding="utf-8")
    assert "analyze_asset" in text
    assert '"asset_types"' in text
    assert "asset_intelligence:" in text
