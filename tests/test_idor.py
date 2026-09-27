import httpx

from h1_agent.idor import ObjectAuthorizationTester


class Scope:
    asset_type = "DOMAIN"
    asset_identifier = "example.com"
    eligible_for_submission = True
    eligible_for_bounty = True
    instruction = ""
    id = "1"
    max_severity = None
    confidentiality_requirement = None
    integrity_requirement = None
    availability_requirement = None
    reference = None


class FakeClient:
    def __init__(self, bodies):
        self.bodies = bodies

    def get(self, url, *, headers, follow_redirects=False):
        account = headers["Authorization"]
        status, body = self.bodies[account]
        return httpx.Response(
            status,
            request=httpx.Request("GET", url),
            headers={"content-type": "application/json"},
            text=body,
        )


def test_bola_requires_exact_same_object_and_owner_binding():
    client = FakeClient({
        "A": (200, '{"id":"123","ownerId":"A-OWNER-42","secret":"alpha"}'),
        "B": (200, '{"id":"123","ownerId":"A-OWNER-42","secret":"alpha"}'),
    })
    tester = ObjectAuthorizationTester(
        client,
        "Authorization: A",
        "Authorization: B",
        max_urls=4,
    )
    observations, evidence = tester.run(["https://example.com/api/documents/123"], [Scope()])

    assert len(observations) == 1
    assert observations[0].suspicious is True
    assert observations[0].object_id == "123"
    assert observations[0].ownership_binding == "ownerId=A-OWNER-42"
    assert any(item.name == "idor_same_object_access" and item.value == "true" for item in evidence)
    assert any(item.name == "idor_ownership_binding" and item.value == "true" for item in evidence)


def test_bola_does_not_flag_when_owner_binding_is_not_reproduced():
    client = FakeClient({
        "A": (200, '{"id":"123","ownerId":"A-OWNER-42","secret":"alpha"}'),
        "B": (200, '{"id":"123","ownerId":"B-OWNER-99","secret":"public"}'),
    })
    tester = ObjectAuthorizationTester(client, "Authorization: A", "Authorization: B")
    observations, _ = tester.run(["https://example.com/api/documents/123"], [Scope()])

    assert observations[0].suspicious is False


def test_bola_rejects_identical_test_headers():
    client = FakeClient({})
    try:
        ObjectAuthorizationTester(client, "Authorization: A", "Authorization: A")
    except ValueError:
        return
    raise AssertionError("expected identical test-account headers to be rejected")
