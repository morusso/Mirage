import httpx
import pytest

PATHS = ["/phpmyadmin/", "/phpmyadmin/index.php", "/phpmyadmin", "/phpMyAdmin/", "/pma/", "/mysql/"]


@pytest.mark.parametrize("path", PATHS)
async def test_login_page_on_common_prefixes(client: httpx.AsyncClient, path: str) -> None:
    response = await client.get(path)

    assert response.status_code == 200
    assert 'name="pma_username"' in response.text
    assert response.headers["server"].startswith("Apache/")
    assert response.headers["x-powered-by"].startswith("PHP/")
    assert "phpMyAdmin=" in response.headers["set-cookie"]


async def test_form_posts_back_to_the_prefix_it_was_served_from(client: httpx.AsyncClient) -> None:
    response = await client.get("/pma/")

    assert 'action="/pma/index.php"' in response.text


async def test_login_always_fails_with_mysql_error(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/phpmyadmin/index.php", data={"pma_username": "root", "pma_password": ""}
    )

    assert response.status_code == 200
    assert "Access denied for user 'root'@'localhost' (using password: NO)" in response.text
    assert "location" not in response.headers


async def test_password_flag_reflects_submission(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/phpmyadmin/index.php", data={"pma_username": "root", "pma_password": "toor"}
    )

    assert "password: YES" in response.text


async def test_missing_username(client: httpx.AsyncClient) -> None:
    response = await client.post("/phpmyadmin/index.php", data={"pma_username": ""})

    assert "Cannot log in to the MySQL server" in response.text


async def test_submitted_username_is_html_escaped(client: httpx.AsyncClient) -> None:
    payload = '"><script>alert(1)</script>'
    response = await client.post(
        "/phpmyadmin/index.php", data={"pma_username": payload, "pma_password": "x"}
    )

    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


async def test_malformed_body_does_not_crash(client: httpx.AsyncClient) -> None:
    response = await client.post("/phpmyadmin/index.php", content=b"\xff\xfe&&=%zz")

    assert response.status_code == 200


async def test_readme_discloses_version(client: httpx.AsyncClient) -> None:
    response = await client.get("/phpmyadmin/README")

    assert "Version 5.2.1" in response.text


async def test_unrelated_path_under_prefix_is_404(client: httpx.AsyncClient) -> None:
    response = await client.get("/phpmyadmin/setup/index.php")

    assert response.status_code == 404
