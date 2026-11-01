import httpx
from fastapi import FastAPI

from domain.captured_request import CapturedRequest


class RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[CapturedRequest] = []

    async def publish(self, event: CapturedRequest) -> bool:
        self.events.append(event)
        return True


async def test_every_request_is_published(app: FastAPI, client: httpx.AsyncClient) -> None:
    recorder = RecordingPublisher()
    app.state.publisher = recorder

    await client.get("/wp-admin/setup-config.php", headers={"user-agent": "nuclei"})
    await client.post("/api/v1/auth/login", json={"email": "a", "password": "b"})

    assert [(e.method, e.path) for e in recorder.events] == [
        ("GET", "/wp-admin/setup-config.php"),
        ("POST", "/api/v1/auth/login"),
    ]
    assert recorder.events[0].world_id != recorder.events[1].world_id


async def test_body_still_reaches_the_handler(app: FastAPI, client: httpx.AsyncClient) -> None:
    app.state.publisher = RecordingPublisher()

    response = await client.post(
        "/api/v1/auth/login", json={"email": "olivia.bennett@example.com", "password": "password"}
    )

    assert response.status_code == 200
