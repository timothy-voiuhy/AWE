"""System API handlers and helpers."""

from ..config import Settings
from ..config import get_settings
from ..schemas import DatabaseCleanupResult
from ..schemas import DatabaseCollectionStats
from ..schemas import DatabaseOverview
from ..schemas import DatabaseStats
from ..schemas import JwtScanRequest
from fastapi import Depends
from fastapi import HTTPException
from fastapi.responses import FileResponse
from pymongo import MongoClient
from pymongo.errors import PyMongoError
import docker
from fastapi import APIRouter

router = APIRouter()


@router.post("/jwt/scan", tags=["jwt"])
def scan_jwt(payload: JwtScanRequest) -> dict:
    """Run jwt_tool in an isolated Docker container for the web workbench."""
    args = [payload.token]
    if payload.url and payload.mode != "decode":
        args += ["-t", payload.url]
        if payload.cookie:
            args += ["-rc", f"{payload.cookie}={payload.token}"]
        elif payload.header:
            args += ["-rh", f"{payload.header} {payload.token}"]
        args += ["-M", payload.mode]
    try:
        client = docker.from_env()
        output = client.containers.run("ticarpi/jwt_tool", args=args, remove=True, stdout=True, stderr=True)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull("ticarpi/jwt_tool")
            output = client.containers.run("ticarpi/jwt_tool", args=args, remove=True, stdout=True, stderr=True)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"jwt_tool unavailable: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"jwt_tool failed: {exc}") from exc
    return {"output": output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)}


@router.get("/proxy/info", tags=["proxy"])
def proxy_info(settings: Settings = Depends(get_settings)) -> dict:
    return {
        "host": settings.proxy_advertise_host,
        "port": settings.proxy_public_port,
        "certificate_url": "/api/v1/proxy/certificate",
        "scheme": "http",
        "username": settings.proxy_username,
        "password_configured": bool(settings.proxy_password),
    }


@router.get("/proxy/certificate", tags=["proxy"])
def download_proxy_certificate(settings: Settings = Depends(get_settings)) -> FileResponse:
    certificate = settings.proxy_certificate_path
    if not certificate.is_file():
        raise HTTPException(status_code=503, detail="Proxy certificate is not available yet")
    return FileResponse(certificate, media_type="application/x-x509-ca-cert", filename="awe-proxy-ca.crt")


def _mongo_collection_stats(database, collection_name: str) -> DatabaseCollectionStats:
    """Return lightweight Mongo collection statistics for the admin page."""
    stats = database.command("collStats", collection_name)
    return DatabaseCollectionStats(
        name=collection_name,
        documents=int(stats.get("count", 0)),
        storage_bytes=int(stats.get("storageSize", 0)),
        index_bytes=int(stats.get("totalIndexSize", 0)),
    )


@router.get("/database/overview", response_model=DatabaseOverview, tags=["database"])
def database_overview(settings: Settings = Depends(get_settings)) -> DatabaseOverview:
    """Return database and collection sizes without exposing stored contents."""
    try:
        with MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000) as client:
            databases: list[DatabaseStats] = []
            for database_name in sorted(client.list_database_names()):
                if database_name in {"admin", "config", "local"}:
                    continue
                database = client[database_name]
                collections: list[DatabaseCollectionStats] = []
                for collection_name in sorted(database.list_collection_names()):
                    if collection_name.startswith("system."):
                        continue
                    try:
                        collections.append(_mongo_collection_stats(database, collection_name))
                    except PyMongoError:
                        # A collection can disappear while a cleanup operation
                        # is running. It should not make the whole dashboard fail.
                        continue
                if collections:
                    databases.append(DatabaseStats(
                        name=database_name,
                        documents=sum(item.documents for item in collections),
                        storage_bytes=sum(item.storage_bytes for item in collections),
                        index_bytes=sum(item.index_bytes for item in collections),
                        collections=collections,
                    ))
            return DatabaseOverview(databases=databases)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.delete("/database/traffic", response_model=DatabaseCleanupResult, tags=["database"])
def clear_all_proxy_traffic(settings: Settings = Depends(get_settings)) -> DatabaseCleanupResult:
    """Drop every captured proxy transaction and recreate its indexes.

    This is intentionally global: proxy traffic is shared by projects and can
    include captures from external devices. The UI must therefore require an
    explicit confirmation before calling this endpoint.
    """
    database_name = "awe_proxy_traffic"
    collection_name = "traffic"
    try:
        with MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000) as client:
            database = client[database_name]
            try:
                stats = database.command("collStats", collection_name)
            except PyMongoError:
                stats = {}
            deleted_documents = int(stats.get("count", 0))
            released_storage = int(stats.get("storageSize", 0)) + int(stats.get("totalIndexSize", 0))
            database.drop_collection(collection_name)

            # Keep the proxy collection ready for new captures immediately;
            # dropping the collection also removes its old indexes.
            traffic = database[collection_name]
            traffic.create_index("host")
            traffic.create_index("project_id")
            traffic.create_index([("host", 1), ("timestamp", -1)])
            traffic.create_index([("host", 1), ("method", 1), ("path", 1)])
            return DatabaseCleanupResult(
                database=database_name,
                collection=collection_name,
                deleted_documents=deleted_documents,
                reclaimed_storage_bytes=released_storage,
            )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
