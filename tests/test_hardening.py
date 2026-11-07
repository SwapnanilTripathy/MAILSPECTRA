import pytest
from httpx import AsyncClient, ASGITransport
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from backend.app.core.request_limits import RequestBodyLimit
from backend.app.main import app


@pytest.mark.asyncio
async def test_chunked_body_is_limited_before_endpoint():
    calls = []
    async def endpoint(request):
        calls.append(True)
        return JSONResponse({'length': len(await request.body())})
    bounded = RequestBodyLimit(Starlette(routes=[Route('/', endpoint, methods=['POST'])]), max_bytes=10)
    async def chunks():
        yield b'123456'
        yield b'789012'
    async with AsyncClient(transport=ASGITransport(app=bounded), base_url='http://test') as client:
        assert (await client.post('/', content=chunks())).status_code == 413
        assert not calls
        assert (await client.post('/', content=b'123')).json() == {'length': 3}


@pytest.mark.asyncio
async def test_request_headers_and_readiness():
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        response = await client.get('/api/v1/health')
        assert response.headers['x-content-type-options'] == 'nosniff'
        assert response.headers['cache-control'] == 'no-store'
        assert len(response.headers['x-request-id']) == 32
        assert (await client.get('/api/v1/ready')).status_code == 200
        traversal = await client.get('/%2e%2e/%2e%2e/.env')
        assert traversal.status_code == 404
