import pytest
from httpx import AsyncClient
from fastapi import status
from unittest.mock import patch
from main import app  # update if your app is in a different file


@pytest.mark.asyncio
@patch("main.decode_token")
@patch("main.httpx.AsyncClient.request")
async def test_proxy_authenticated_route(mock_request, mock_decode):
    # Mock decoded token
    mock_decode.return_value = {"sub": "123", "role": "admin"}

    # Mock backend service response
    mock_request.return_value.status_code = 200
    mock_request.return_value.json.return_value = {"data": "ok"}

    headers = {"Authorization": "Bearer faketoken"}
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/example", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"data": "ok"}
    mock_request.assert_called_once()


@pytest.mark.asyncio
async def test_proxy_missing_auth_header():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/example")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Authorization header missing" in response.text


@pytest.mark.asyncio
@patch("main.httpx.AsyncClient.request")
async def test_forward_unauthenticated(mock_request):
    mock_request.return_value.status_code = 200
    mock_request.return_value.json.return_value = {"token": "abc"}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/auth/login", json={"username": "a", "password": "b"})

    assert response.status_code == 200
    assert response.json() == {"token": "abc"}
    mock_request.assert_called_once()
