"""Bound request bytes, including chunked bodies, before parsing JSON or MIME."""
from starlette.responses import JSONResponse


class RequestBodyLimit:
    def __init__(self, app, max_bytes):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] not in {'POST', 'PUT', 'PATCH'}:
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            if len(body) + len(chunk) > self.max_bytes:
                response = JSONResponse({'detail': 'Request body exceeds limit', 'code': 'PAYLOAD_TOO_LARGE'}, status_code=413)
                return await response(scope, receive, send)
            body.extend(chunk)
            if not message.get('more_body', False):
                break
        pending = True

        async def replay():
            nonlocal pending
            if pending:
                pending = False
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()

        return await self.app(scope, replay, send)
