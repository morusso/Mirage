from pathlib import Path

import pytest
from jinja2 import Environment, TemplateNotFound, UndefinedError

from app.engine.templates import create_environment, render_template


def _env(tmp_path: Path, files: dict[str, str]) -> Environment:
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    return create_environment(tmp_path)


def test_renders_packaged_template() -> None:
    page = render_template("nginx_404.html", server="nginx/1.24.0")

    assert "<hr><center>nginx/1.24.0</center>" in page
    assert page.endswith("</html>\n")


def test_html_context_is_autoescaped(tmp_path: Path) -> None:
    env = _env(tmp_path, {"t.html": "{{ v }}"})

    assert (
        env.get_template("t.html").render(v="<script>x</script>")
        == "&lt;script&gt;x&lt;/script&gt;"
    )


def test_non_html_templates_are_not_escaped(tmp_path: Path) -> None:
    env = _env(tmp_path, {"t.env": "{{ v }}"})

    assert env.get_template("t.env").render(v="a&b<c") == "a&b<c"


def test_missing_variable_raises(tmp_path: Path) -> None:
    env = _env(tmp_path, {"t.html": "{{ missing }}"})

    with pytest.raises(UndefinedError):
        env.get_template("t.html").render()


def test_unknown_template_raises() -> None:
    with pytest.raises(TemplateNotFound):
        render_template("does_not_exist.html")


def test_template_name_cannot_escape_templates_dir() -> None:
    with pytest.raises(TemplateNotFound):
        render_template("../config.py")
