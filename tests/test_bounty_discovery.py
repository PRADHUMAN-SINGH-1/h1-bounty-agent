from h1_agent.discovery import rank
from h1_agent.hackerone import HackerOneClient
from h1_agent.models import ScopeAsset


def _scope(identifier: str, *, bounty: bool = True, severity: str = "high") -> ScopeAsset:
    return ScopeAsset(
        id="1",
        asset_type="DOMAIN",
        asset_identifier=identifier,
        eligible_for_bounty=bounty,
        eligible_for_submission=True,
        instruction="",
        max_severity=severity,
        confidentiality_requirement="high",
        integrity_requirement="high",
        availability_requirement="high",
        reference="H1TEST",
    )


def test_non_bounty_programs_are_never_ranked_above_paid_programs():
    paid = rank("paid", "Paid", "public", [_scope("paid.example")])
    vdp = rank("vdp", "VDP", "public", [_scope("vdp.example", bounty=False)])
    assert paid.score > vdp.score
    assert vdp.score < 0


def test_program_catalog_paginates_until_short_page(monkeypatch):
    client = HackerOneClient.__new__(HackerOneClient)
    pages = {
        1: {"data": [{"id": "1"}] * 100},
        2: {"data": [{"id": "2"}] * 3},
    }

    def fake_page(page, page_size):
        return pages[page]

    monkeypatch.setattr(client, "_programs_page", fake_page)
    result = client.programs_all(page_size=100, max_pages=20)
    assert result["meta"]["pages_fetched"] == 2
    assert result["meta"]["count"] == 103


def test_structured_scope_catalog_paginates_until_short_page(monkeypatch):
    client = HackerOneClient.__new__(HackerOneClient)
    pages = {
        1: {"data": [{"id": str(i)} for i in range(100)]},
        2: {"data": [{"id": "101"}]},
    }

    def fake_page(handle, page, page_size):
        return pages[page]

    monkeypatch.setattr(client, "_structured_scopes_page", fake_page)
    result = client.structured_scopes_all("example", page_size=100, max_pages=20)
    assert len(result["data"]) == 101
