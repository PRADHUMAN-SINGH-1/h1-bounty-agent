from pathlib import Path

from h1_agent.config import Settings
from h1_agent.worker import _select_targets


class Asset:
    def __init__(self, identifier, asset_type="DOMAIN", eligible=True, bounty=True, instruction=""):
        self.asset_identifier = identifier
        self.asset_type = asset_type
        self.eligible_for_submission = eligible
        self.eligible_for_bounty = bounty
        self.instruction = instruction


def test_full_research_can_select_broad_scope():
    assets = [Asset(f"app{i}.example.com") for i in range(8)]
    selected = _select_targets(assets, 50, exhaustive=True)
    assert len(selected) == 8
    assert len({target for _, target in selected}) == 8


def test_target_selection_skips_instructional_assets():
    assets = [
        Asset("ok.example.com"),
        Asset("skip.example.com", instruction="Do not test"),
        Asset("other.example.com"),
    ]
    selected = _select_targets(assets, 50, exhaustive=True)
    assert [target for _, target in selected] == [
        "https://ok.example.com",
        "https://other.example.com",
    ]


def test_deep_settings_are_expanded():
    settings = Settings()
    assert settings.full_research_max_targets_per_program >= 25
    assert settings.deep_max_scripts >= 20
    assert settings.deep_max_api_candidates >= 20


def test_async_job_api_exists():
    source = Path("api/index.py").read_text(encoding="utf-8")
    assert '@app.post("/api/research/jobs")' in source
    assert '@app.get("/api/research/jobs/{job_id}")' in source
    assert "BackgroundTasks" in source
    assert "_run_research_job" in source


def test_dashboard_polls_research_jobs():
    html = Path("public/index.html").read_text(encoding="utf-8")
    assert "/api/research/jobs" in html
    assert "pollResearchJob" in html
    assert "Progress:" in html
