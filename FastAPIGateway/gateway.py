import jwt
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Configs (set these via environment variables or Docker)
JWT_SECRET = os.getenv("JWT_SECRET", "django-insecure-o@sx!a5==cevdjqe#=&hmo#rq)@(rw!^93vg0=0x07n@+rb2bq")
ALGORITHM = "HS256"

# Docker-based service names (use container service names here)
# Key = public first segment
# Value = (target_base_url, internal_path_prefix)
SERVICE_ROUTES = {
    "auth": (os.getenv("AUTH_SERVICE_URL", "http://localhost:8001"), "/api/v1"),
    "fleet": (os.getenv("FLEET_SERVICE_URL", "http://localhost:8002"), "/api/fleet"),
    "shipments": (os.getenv("SHIPMENTS_SERVICE_URL", "http://localhost:8002"), "/api/shipments"),
    "assignments": (os.getenv("ASSIGNMENTS_SERVICE_URL", "http://localhost:8003"), "/api/assignments"),
    "monitoring": (os.getenv("MONITORING_SERVICE_URL", "http://localhost:8004"), "/api/monitoring"),
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
            target_url, internal_prefix = SERVICE_ROUTES[first_segment]
            # Rewrite the path by removing the public prefix and adding the internal one
            rewritten_path = "/" + "/".join(path_parts[3:])  # remove 'api/v1/auth'
            return target_url, internal_prefix.rstrip("/") + rewritten_path
    return None, None


# Catch-all proxy endpoint
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    normalized_path = "/" + path
    print(f"\n🔵 Incoming Request Path: {normalized_path}")
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
        print("🔓 Unauthenticated path - forwarding without auth check")  # <-- added
        return await forward_unauthenticated(request, normalized_path)

    # Auth required
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")

    token = auth_header[7:]
    claims = decode_token(token)

    target_url, rewritten_path = get_target_service(normalized_path)
    if not target_url:
        raise HTTPException(status_code=404, detail="No matching service route")

    # Log the forwarding destination
    full_target = f"{target_url}{rewritten_path}"
    print(f"➡️ Forwarding to: {full_target}")

    async with httpx.AsyncClient() as client:
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
