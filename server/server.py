import logging
import os
import time
from typing import Annotated

from client import (
    ClientManager,
)
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import PlainTextResponse
from models import (
    ErrorResponse,
    ResetResponse,
    CacheStats,
    SecretResponse,
    StatsResponse,
    HealthcheckResponse,
)
from prom_client import PromMetricsClient

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

root_logger = logging.getLogger()

logger = logging.getLogger("bwscache.server")

LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING").upper()

mode_mapping = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


root_logger.setLevel(mode_mapping[LOG_LEVEL])

if root_logger.level == logging.DEBUG:
    formatter = logging.Formatter(
        "[%(asctime)s] {%(pathname)s:%(lineno)d} %(name)s:%(levelname)s - %(message)s",
        "%m-%d %H:%M:%S",
    )
else:
    formatter = logging.Formatter("%(asctime)s - %(name)s:%(levelname)s - %(message)s")

ch = logging.StreamHandler()
ch.setFormatter(formatter)
root_logger.addHandler(ch)

api = FastAPI()


prom_client = PromMetricsClient()
client_manager = ClientManager(prom_client)


@api.middleware("http")
async def prom_middleware(request: Request, call_next):
    api_mapping = [
        "/reset",
        "/id",
        "/key",
    ]
    endpoint = None
    for api_endpoint in api_mapping:
        if request.url.path.startswith(api_endpoint):
            endpoint = request.url.path
    st = time.time()
    return_data: Response = await call_next(request)
    if endpoint and isinstance(return_data, Response):
        prom_client.tick_http_request_total(endpoint, str(return_data.status_code))
        prom_client.tick_http_request_duration(endpoint, time.time() - st)
    prom_client.tick_stats(client_manager.stats())
    return return_data


def custom_openapi():
    if api.openapi_schema:
        return api.openapi_schema
    openapi_schema = get_openapi(
        title="bws-cache",
        version="1.1.0",
        summary="bws-cache OpenAPI Schema",
        description='<a href="https://github.com/rippleFCL/bws-cache">Github</a> | <a href="https://github.com/rippleFCL/bws-cache/issues">Issues</a>',
        routes=api.routes,
    )
    api.openapi_schema = openapi_schema
    return api.openapi_schema


api.openapi = custom_openapi


def handle_auth(authorization: Annotated[str, Header()]):
    if authorization.startswith("Bearer "):
        return authorization.split()[-1]
    raise HTTPException(status_code=401, detail="Invalid token")


@api.get(
    "/reset",
    response_model=ResetResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or unauthorised token"},
    },
)
def reset_cache(authorization: Annotated[str, Depends(handle_auth)]):
    client = client_manager.get_client_by_token(authorization)
    stats = client.reset_cache()
    return ResetResponse(
        status="success",
        before=stats,
        after=CacheStats(secret_cache_size=0, keymap_cache_size=0),
    )


@api.get(
    "/id/{secret_id}",
    response_model=SecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or unauthorised token"},
        404: {"model": ErrorResponse, "description": "Secret not found"},
        429: {
            "model": ErrorResponse,
            "description": "BWS authentication endpoint rate limited",
        },
    },
)
def get_id(authorization: Annotated[str, Depends(handle_auth)], secret_id: str):
    client = client_manager.get_client_by_token(authorization)
    secret = client.get_secret_by_id(secret_id)
    return Response(content=secret.value, status_code=secret.status_code)


@api.get(
    "/key/{secret_key}",
    response_model=SecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or unauthorised token"},
        404: {"model": ErrorResponse, "description": "Key not found"},
        429: {
            "model": ErrorResponse,
            "description": "BWS authentication endpoint rate limited",
        },
    },
)
def get_key(
    authorization: Annotated[str, Depends(handle_auth)],
    secret_key: str,
):
    client = client_manager.get_client_by_token(authorization)
    secret = client.get_secret_by_key(secret_key)
    return Response(content=secret.value, status_code=secret.status_code)


@api.get(
    "/metrics",
    response_class=PlainTextResponse,
    responses={
        200: {
            "description": "Successful response with metrics data",
        },
        500: {
            "model": ErrorResponse,
            "content": {
                "application/json": {"schema": ErrorResponse.model_json_schema()}
            },
            "description": "Internal server error",
        },
    },
)
def prometheus_metrics(accept: Annotated[str | str, Header()] = ""):
    generated_data, content_type = prom_client.generate_metrics(accept)
    headers = {"Content-Type": content_type}
    return PlainTextResponse(generated_data, headers=headers)


@api.get(
    "/stats",
    response_model=StatsResponse,
    responses={
        200: {
            "model": StatsResponse,
            "description": "Successful response with stats data",
        },
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
def get_stats():
    return client_manager.stats()


@api.get("/healthcheck", response_model=HealthcheckResponse)
def healthcheck():
    return {"status": "I'm alive"}
