from typing import List
import jwt
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx
import os
from dotenv import load_dotenv
import logging


load_dotenv()

# Configure logger
logger = logging.getLogger("gateway")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

app = FastAPI()

# Configs (set these via environment variables or Docker)
JWT_SECRET = os.getenv("JWT_SECRET", "django-insecure-o@sx!a5==cevdjqe#=&hmo#rq)@(rw!^93vg0=0x07n@+rb2bq")
ALGORITHM = "HS256"

# Docker-based service names (use container service names here)
# Key = public first segment
# Value = (target_base_url, internal_path_prefix)
SERVICE_ROUTES = {
    "auth": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8003"), "/api/v1", [2]),
    "admin": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8003"), "/api/v1/admin", [2]),
    "me": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8003"), "/api/v1/me", [2]),
    "login": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8003"), "/api/v1/login", [2]),
    "logout": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8003"), "/api/v1/logout", [2]),
    "register": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8003"), "/api/v1/register", [2]),

    "fleet": (os.getenv("LOGISTICS_SERVICE_URL", "http://localhost:8002"), "/api/fleet", [2]),
    "shipments": (os.getenv("LOGISTICS_SERVICE_URL", "http://localhost:8002"), "/api/shipments", [2]),
    "assignments": (os.getenv("LOGISTICS_SERVICE_URL", "http://localhost:8002"), "/api/assignments", [2]),
    "monitoring": (os.getenv("LOGISTICS_SERVICE_URL", "http://localhost:8002"), "/api/monitoring", [2]),

    "orders": (os.getenv("ORDER_SERVICE_URL", "http://localhost:8000"), "/api/v0/orders", [2]),
    "supplier-request": (os.getenv("ORDER_SERVICE_URL", "http://localhost:8000"), "/api/v0/supplier-request", [2]),

    "warehouse": (os.getenv("WAREHOUSE_SERVICE_URL", "http://localhost:8001"), "/api/warehouse", [2]),
    "product": (os.getenv("WAREHOUSE_SERVICE_URL", "http://localhost:8001"), "/api/product", [2]),

    "forecast": (os.getenv("FORECAST_SERVICE_URL", "http://localhost:8005"), "/api/forcast", [2]),
    "ranking": (os.getenv("RANKING_SERVICE_URL", "http://localhost:8004"), "/api/ranking", [2]),
}


# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT decoding helper
def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_target_service(path: str):
    path_parts = path.lstrip("/").split("/")
    if len(path_parts) >= 3 and path_parts[0] == "api" and path_parts[1] == "v1":
        first_segment = path_parts[2]  # e.g., "auth"
        if first_segment in SERVICE_ROUTES:
            target_url, internal_prefix, allowed_roles = SERVICE_ROUTES[first_segment]
            # Rewrite the path by removing the public prefix and adding the internal one
            rewritten_path = "/" + "/".join(path_parts[3:])  # remove 'api/v1/auth'
            return target_url, internal_prefix.rstrip("/") + rewritten_path, allowed_roles
    return None, None, []

def check_if_authorized(token: str, role_ids = List[int]):
    """
    admin - 1
    user - 2
    supplier - 3
    vendor - 4
    warehouse_manager - 5
    driver - 6

    specially gives all access if 2 is in the list of role id's
    """
    if 2 in role_ids:
        return True
    
    payload = decode_token(token)
    role_id = payload.get("role_id")
    if (not role_id):
        return False
    
    for i in role_ids:
        if i == role_id:
            return True
    else:
        return False

# Catch-all proxy endpoint
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    normalized_path = "/" + path
    logger.info(f"Incoming Request Path: {normalized_path}")
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return JSONResponse(content={"message": "OK"}, status_code=200)

    # Unauthenticated endpoints (can be expanded)
    unauthenticated_paths = [
        "/api/v1/register/",
        "/api/v1/login/",
        "/api/v1/password/reset/",
        "/api/v1/password/reset-confirm/",
        "/api/v1/token/refresh/",
        "/api/v1/token/verify/",
        "/api/v1/swagger/",
    ]
    if any(normalized_path.startswith(p) for p in unauthenticated_paths):
        logger.info("Unauthenticated path - forwarding without auth check")
        return await forward_unauthenticated(request, normalized_path)

    # Auth required
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")

    token = auth_header[7:]
    claims = decode_token(token)

    target_url, rewritten_path, allowed_roles = get_target_service(normalized_path)
    # logger.debug(f"Target Service URL: {target_url}, Rewritten Path: {rewritten_path}")
    # return f"🔍 Target Service URL: {target_url}, Rewritten Path: {rewritten_path}, Accessible? {check_if_authorized(token, allowed_roles)}"
    if not target_url:
        raise HTTPException(status_code=404, detail="No matching service route")

    is_authorized = check_if_authorized(token, allowed_roles)
    if not is_authorized:
        raise HTTPException(status_code=401, detail="Unauthorized service request.")

    # Log the forwarding destination
    full_target = f"{target_url}{rewritten_path}"
    logger.info(f"Forwarding to: {full_target}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        body = await request.body()
        headers = dict(request.headers)
        headers["X-User-ID"] = str(claims.get("sub"))
        headers["X-User-Role"] = claims.get("role", "")


        resp = await client.request(
            method=request.method,
            url=f"{target_url}{rewritten_path}",
            content=body,
            headers=headers,
            params=dict(request.query_params),
        )
        try:
            content = resp.json()
        except Exception:
            content = resp.text

        return JSONResponse(content=content, status_code=resp.status_code)

# Forward public auth requests
async def forward_unauthenticated(request: Request, path: str):
    auth_service_url = SERVICE_ROUTES["auth"][0]
    async with httpx.AsyncClient() as client:
        body = await request.body()
        headers = dict(request.headers)
        host = request.headers.get("host", "")
        headers["host"] = host.split(":")[0]  # Keep only domain part

        resp = await client.request(
            method=request.method,
            url=f"{auth_service_url}{path}",
            content=body,
            headers=headers,
            params=dict(request.query_params),
        )

        try:
            content = resp.json()
        except Exception:
            content = resp.text

        return JSONResponse(content=content, status_code=resp.status_code)
