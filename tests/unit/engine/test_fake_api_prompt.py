from app.engine.prompts.builder import build_messages
from app.engine.prompts.fake_api import FAKE_API_PROMPT
from app.personas.fake_api import FAKE_API_PERSONA, api_router
from tests.unit.engine.test_prompt_builder import _req


def test_prompt_never_reveals_what_the_service_is() -> None:
    lowered = FAKE_API_PROMPT.lower()
    for word in ("honeypot", "simulat", "language model", " ai "):
        assert word not in lowered


def test_prompt_names_every_resource_the_tier0_router_serves() -> None:
    paths = [getattr(r, "path", "") for r in api_router.routes]
    resources = {p.split("/")[3] for p in paths if p.count("/") >= 3}

    assert resources  # guards against the router layout changing under this test
    for resource in resources:
        assert resource in FAKE_API_PROMPT


def test_prompt_matches_the_persona_stack() -> None:
    assert FAKE_API_PERSONA.powered_by is not None
    assert FAKE_API_PERSONA.powered_by in FAKE_API_PROMPT


def test_persona_text_goes_to_the_system_message_verbatim() -> None:
    messages = build_messages(persona_prompt=FAKE_API_PROMPT, request=_req())

    assert FAKE_API_PROMPT in messages[0].content
