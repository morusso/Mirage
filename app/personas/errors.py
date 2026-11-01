from app.personas.base import PersonaConfig


def nginx_404_page(persona: PersonaConfig) -> str:
    """Byte-for-byte nginx 404 page (CRLF line endings, footer shows the server banner)."""
    return (
        "<html>\r\n"
        "<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>404 Not Found</h1></center>\r\n"
        f"<hr><center>{persona.server}</center>\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )
