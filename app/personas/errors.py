from app.engine.templates import render_template
from app.personas.base import PersonaConfig


def nginx_404_page(persona: PersonaConfig) -> str:
    """nginx 404 page: CRLF line endings, footer shows the server banner."""
    page = render_template("nginx_404.html", server=persona.server)
    return page.replace("\n", "\r\n")
