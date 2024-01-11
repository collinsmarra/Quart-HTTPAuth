import base64
from quart import Quart, Response
from src.quart_httpauth import HTTPBasicAuth
import pytest


class TestHTTPAuth:
    @pytest.fixture
    def app(self):
        app = Quart(__name__)
        app.config["SECRET_KEY"] = "my secret"

        self.basic_verify_auth = HTTPBasicAuth()

        @self.basic_verify_auth.verify_password
        def verify_password(username, password):
            return False

        @self.basic_verify_auth.error_handler
        def error_handler():
            assert self.basic_verify_auth.current_user() is None
            return self.error_response

        @app.route("/")
        @self.basic_verify_auth.login_required
        async def index():
            return "index"

        return app

    @pytest.mark.asyncio
    async def test_default_status_code(self, app):
        client = app.test_client()
        creds = base64.b64encode(b"foo:bar").decode("utf-8")

        responses = [
            ["error", 401],
            [("error", 403), 403],
            [("error", 200), 200],
            [Response("error"), 200],
            [Response("error", 403), 403],
        ]

        for r in responses:
            self.error_response = r[0]
            response = await client.get(
                "/", headers={"Authorization": "Basic " + creds}
            )
            assert response.status_code == r[1]
