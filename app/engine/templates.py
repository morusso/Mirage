"""Jinja2 loader for tier 0 (static) responses.

Templates are trusted, repository-owned files. Attacker-controlled data may only
ever be passed as template *context*, never as template source.
"""

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_environment(templates_dir: Path = TEMPLATES_DIR) -> Environment:
    return Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )


_environment = create_environment()


def render_template(name: str, **context: Any) -> str:
    return _environment.get_template(name).render(**context)
