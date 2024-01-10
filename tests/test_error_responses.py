import unittest
import base64

from quart import Quart, Response
import quart_flask_patch
from src.flask_httpauth import HTTPBasicAuth


class HTTPAuthTestCase(unittest.TestCase):
    responses = [
        ["error", 401],
        [("error", 403), 403],
        [("error", 200), 200],
        [Response("error"), 200],
        [Response("error", 403), 403],
    ]

    def setUp(self):
        app = Quart(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_verify_auth = HTTPBasicAuth()

        @basic_verify_auth.verify_password
        def basic_verify_auth_verify_password(username, password):
            return False

        @basic_verify_auth.error_handler
        def error_handler():
            self.assertIsNone(basic_verify_auth.current_user())
            return self.error_response

        @app.route("/")
        @basic_verify_auth.login_required
        def index():
            return "index"

        self.app = app
        self.basic_verify_auth = basic_verify_auth
        self.client = app.test_client()

    async def test_default_status_code(self):
        creds = base64.b64encode(b"foo:bar").decode("utf-8")

        for r in self.responses:
            self.error_response = r[0]
            response = await self.client.get(
                "/", headers={"Authorization": "Basic " + creds}
            )
            self.assertEqual(response.status_code, r[1])
