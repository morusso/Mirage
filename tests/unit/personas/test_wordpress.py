from urllib.parse import parse_qs, urlsplit

import httpx


async def test_login_page_sets_test_cookie_and_persona_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/wp-login.php")

    assert response.status_code == 200
    assert 'name="log"' in response.text
    assert "wordpress_test_cookie" in response.headers["set-cookie"]
    assert response.headers["server"] == "nginx/1.24.0"
    assert response.headers["x-powered-by"].startswith("PHP/")


async def test_known_username_gets_wrong_password_error(client: httpx.AsyncClient) -> None:
    response = await client.post("/wp-login.php", data={"log": "admin", "pwd": "x"})

    assert "password you entered for the username <strong>admin</strong>" in response.text


async def test_unknown_username_is_distinguishable(client: httpx.AsyncClient) -> None:
    response = await client.post("/wp-login.php", data={"log": "nobody", "pwd": "x"})

    assert "is not registered on this site" in response.text


async def test_never_accepts_a_login(client: httpx.AsyncClient) -> None:
    response = await client.post("/wp-login.php", data={"log": "admin", "pwd": "admin123"})

    assert response.status_code == 200
    assert "login_error" in response.text
    assert "location" not in response.headers


async def test_empty_fields(client: httpx.AsyncClient) -> None:
    no_user = await client.post("/wp-login.php", data={"log": "", "pwd": ""})
    no_pass = await client.post("/wp-login.php", data={"log": "admin", "pwd": ""})

    assert "username field is empty" in no_user.text
    assert "password field is empty" in no_pass.text


async def test_submitted_username_is_html_escaped(client: httpx.AsyncClient) -> None:
    payload = '"><script>alert(1)</script>'
    response = await client.post("/wp-login.php", data={"log": payload, "pwd": "x"})

    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


async def test_malformed_body_does_not_crash(client: httpx.AsyncClient) -> None:
    response = await client.post("/wp-login.php", content=b"\xff\xfe&&=%zz", data=None)

    assert response.status_code == 200


async def test_wp_admin_redirects_to_login(client: httpx.AsyncClient) -> None:
    for path in ("/wp-admin", "/wp-admin/"):
        response = await client.get(path)

        assert response.status_code == 302
        location = urlsplit(response.headers["location"])
        assert location.path == "/wp-login.php"
        assert parse_qs(location.query)["redirect_to"] == [path]


async def test_readme_discloses_version(client: httpx.AsyncClient) -> None:
    response = await client.get("/readme.html")

    assert "Version 6.4.3" in response.text


async def test_xmlrpc(client: httpx.AsyncClient) -> None:
    get = await client.get("/xmlrpc.php")
    post = await client.post("/xmlrpc.php", content="<methodCall/>")

    assert get.status_code == 405
    assert get.text == "XML-RPC server accepts POST requests only."
    assert "<int>403</int>" in post.text
    assert post.headers["content-type"].startswith("text/xml")


async def test_rest_user_enumeration(client: httpx.AsyncClient) -> None:
    response = await client.get("/wp-json/wp/v2/users")

    assert [u["slug"] for u in response.json()] == ["admin"]


async def test_other_wordpress_paths_still_404(client: httpx.AsyncClient) -> None:
    response = await client.get("/wp-content/debug.log")

    assert response.status_code == 404
