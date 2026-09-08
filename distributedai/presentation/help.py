# SPDX-License-Identifier: AGPL-3.0-only
from starlette.responses import JSONResponse
from starlette.routing import Route
from ..application.help import help_content


def help_routes():
    async def help_page(request):
        try:
            return JSONResponse(help_content(request.query_params.get("page", "signin"),
                                             request.query_params.get("q", "")))
        except ValueError:
            return JSONResponse({"error": "Invalid help search"}, 400)
    return [Route("/help", help_page)]
