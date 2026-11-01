from app.personas.base import DEFAULT_PERSONA, PersonaConfig
from app.personas.errors import nginx_404_page


def test_matches_real_nginx_404_page() -> None:
    page = nginx_404_page(PersonaConfig(name="x", server="nginx/1.24.0"))

    assert page == (
        "<html>\r\n"
        "<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>404 Not Found</h1></center>\r\n"
        "<hr><center>nginx/1.24.0</center>\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )


def test_footer_follows_persona_server_banner() -> None:
    persona = PersonaConfig(name="admin", server="nginx/1.18.0 (Ubuntu)")

    assert "<hr><center>nginx/1.18.0 (Ubuntu)</center>" in nginx_404_page(persona)


def test_default_persona_banner_is_consistent_with_header() -> None:
    assert DEFAULT_PERSONA.server in nginx_404_page(DEFAULT_PERSONA)
