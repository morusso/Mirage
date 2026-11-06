import httpx
import pytest

from app.personas.config_leaks import COMMIT
from app.personas.fake_api import ENV_BAIT_CONTEXT


async def test_git_head_and_ref(client: httpx.AsyncClient) -> None:
    head = await client.get("/.git/HEAD")
    ref = await client.get("/.git/refs/heads/main")

    assert head.text == "ref: refs/heads/main\n"
    assert ref.text == f"{COMMIT}\n"
    assert head.headers["content-type"] == "application/octet-stream"
    assert head.headers["server"] == "nginx/1.24.0"
    assert "x-powered-by" not in head.headers


async def test_git_config_is_a_valid_looking_config_with_remote(client: httpx.AsyncClient) -> None:
    text = (await client.get("/.git/config")).text

    assert text.startswith("[core]\n\trepositoryformatversion = 0")
    assert '[remote "origin"]' in text
    assert "github.com/shopnest-dev/shopnest-store.git" in text


async def test_git_logs_and_packed_refs_agree_on_the_commit(client: httpx.AsyncClient) -> None:
    logs = (await client.get("/.git/logs/HEAD")).text
    packed = (await client.get("/.git/packed-refs")).text

    assert COMMIT in logs
    assert f"{COMMIT} refs/heads/main" in packed
    assert len(COMMIT) == 40


@pytest.mark.parametrize("path", ["/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old"])
async def test_wp_config_backups_share_the_env_database_password(
    client: httpx.AsyncClient, path: str
) -> None:
    text = (await client.get(path)).text

    assert text.startswith("<?php")
    assert f"define( 'DB_PASSWORD', '{ENV_BAIT_CONTEXT['db_password']}' );" in text
    assert f"define( 'DB_HOST', '{ENV_BAIT_CONTEXT['db_host']}' );" in text


async def test_aws_credentials(client: httpx.AsyncClient) -> None:
    text = (await client.get("/.aws/credentials")).text

    assert text.startswith("[default]\naws_access_key_id = ")
    assert "AKIA" not in text  # never shaped like a real key


async def test_other_dotfiles_still_404(client: httpx.AsyncClient) -> None:
    for path in ("/.git/index", "/.git/", "/.aws/config"):
        assert (await client.get(path)).status_code == 404
