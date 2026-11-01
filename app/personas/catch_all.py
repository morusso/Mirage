from fastapi import APIRouter, Depends, Response

from app.personas.base import DEFAULT_PERSONA, persona_dependency
from app.personas.errors import nginx_404_page

CATCH_ALL_PERSONA = DEFAULT_PERSONA

router = APIRouter(dependencies=[Depends(persona_dependency(CATCH_ALL_PERSONA))])


@router.api_route(
    "/{path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    include_in_schema=False,
)
async def catch_all(path: str) -> Response:
    # Content-Type is set explicitly: real nginx sends "text/html" without a charset.
    return Response(
        content=nginx_404_page(CATCH_ALL_PERSONA),
        status_code=404,
        headers={"content-type": "text/html"},
    )
