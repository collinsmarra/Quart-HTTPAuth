import sys
import unittest
import base64
import pytest

from quart import Quart, g
from src.quart_httpauth import HTTPBasicAuth


@pytest.mark.skipif(sys.version_info < (3, 7), reason="requires python3.7")
class HTTPAuthTestCase(unittest.TestCase):
    use_old_style_callback = False

    def setUp(self):
        app = Quart(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_verify_auth = HTTPBasicAuth()

        @basic_verify_auth.verify_password
        async def basic_verify_auth_verify_password(username, password):
            if self.use_old_style_callback:  # Access it using self
                g.anon = False
                if username == "john":
                    return password == "hello"
                elif username == "susan":
                    return password == "bye"
                elif username == "":
                    g.anon = True
                    return True
                return False
            else:
                g.anon = False
                if username == "john" and password == "hello":
                    return "john"
                elif username == "susan" and password == "bye":
                    return "susan"
                elif username == "":
                    g.anon = True
                    return ""

        @basic_verify_auth.error_handler
        async def error_handler():
            self.assertIsNone(basic_verify_auth.current_user())
            return "error", 403  # use a custom error status

        @app.route("/")
        async def index():
            return "index"

        @app.route("/basic-verify")
        @basic_verify_auth.login_required
        async def basic_verify_auth_route():
            if self.use_old_style_callback:
                return (
                    "basic_verify_auth:"
                    + basic_verify_auth.username()
                    + " anon:"
                    + str(g.anon)
                )
            else:
                return (
                    "basic_verify_auth:"
                    + basic_verify_auth.current_user()
                    + " anon:"
                    + str(g.anon)
                )

        self.app = app
        self.basic_verify_auth = basic_verify_auth
        self.client = app.test_client()

    @pytest.mark.asyncio
    async def test_verify_auth_login_valid(self):
        creds = base64.b64encode(b"susan:bye").decode("utf-8")
        response = await self.client.get(
            "/basic-verify", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.data, b"basic_verify_auth:susan anon:False")

    @pytest.mark.asyncio
    async def test_verify_auth_login_empty(self):
        response = await self.client.get("/basic-verify")
        self.assertEqual(response.data, b"basic_verify_auth: anon:True")

    @pytest.mark.asyncio
    async def test_verify_auth_login_invalid(self):
        creds = base64.b64encode(b"john:bye").decode("utf-8")
        response = await self.client.get(
            "/basic-verify", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue("WWW-Authenticate" in response.headers)

    @pytest.mark.asyncio
    async def test_verify_auth_login_malformed_password(self):
        creds = "eyJhbGciOieyJp=="
        response = await self.client.get(
            "/basic-verify", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue("WWW-Authenticate" in response.headers)


class HTTPAuthTestCaseOldStyle(HTTPAuthTestCase):
    use_old_style_callback = True
