from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx
import jwt
import os

app = FastAPI()

# Configs (set these in .env or docker-compose)
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
ALGORITHM = "HS256"

# Routes for services based on path prefixes
SERVICE_ROUTES = {
    "/api/": "http://django-service:8000",
    "/user/": "http://user-service:8000"
}

# CORS Middleware (adjust for production)
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

# Determine target backend service from path prefix
def get_target_service(path: str):
    for prefix, target in SERVICE_ROUTES.items():
        if path.startswith(prefix):
            return target
    return None

# Main proxy route
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(request: Request, path: str):
    # Skip auth for login or registration if needed
    if path in ["auth/login", "auth/register"]:
        return await forward_unauthenticated(request, path)

    # Validate JWT from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")

    token = auth_header[7:]
    claims = decode_token(token)

    # Match route to backend service
    target_url = get_target_service("/" + path)
    if not target_url:
        raise HTTPException(status_code=404, detail="No matching service route")

    # Prepare and forward request
    async with httpx.AsyncClient() as client:
        body = await request.body()
        headers = dict(request.headers)
        headers["X-User-ID"] = str(claims.get("sub"))
        headers["X-User-Role"] = claims.get("role", "")
        headers.pop("host", None)

        resp = await client.request(
            method=request.method,
            url=f"{target_url}/{path}",
            content=body,
            headers=headers,
            params=dict(request.query_params)
        )

        return JSONResponse(content=resp.json(), status_code=resp.status_code)

# Publicly accessible routes like login/signup
async def forward_unauthenticated(request: Request, path: str):
    auth_service_url = "http://auth-service:8000"
    async with httpx.AsyncClient() as client:
        body = await request.body()
        headers = dict(request.headers)
        headers.pop("host", None)

        resp = await client.request(
            method=request.method,
            url=f"{auth_service_url}/{path}",
            content=body,
            headers=headers,
            params=dict(request.query_params)
        )

        return JSONResponse(content=resp.json(), status_code=resp.status_code)
