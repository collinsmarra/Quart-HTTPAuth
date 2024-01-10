import base64
import sys
import unittest
import pytest

from quart import Quart
import quart_flask_patch
from src.flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth


@pytest.mark.skipif(sys.version_info < (3, 7), reason="requires python3.7")
class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Quart(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_auth = HTTPBasicAuth()
        token_auth = HTTPTokenAuth("MyToken")
        custom_token_auth = HTTPTokenAuth(header="X-Token")
        multi_auth = MultiAuth(basic_auth, token_auth, custom_token_auth)

        @basic_auth.verify_password
        async def verify_password(username, password):
            if username == "john" and password == "hello":
                return "john"

        @basic_auth.get_user_roles
        async def get_basic_role(username):
            if username == "john":
                return ["foo", "bar"]

        @token_auth.verify_token
        async def verify_token(token):
            return token == "this-is-the-token!"

        @token_auth.get_user_roles
        async def get_token_role(auth):
            if auth.token == "this-is-the-token!":
                return "foo"
            return

        @token_auth.error_handler
        async def error_handler():
            return "error", 401, {"WWW-Authenticate": 'MyToken realm="Foo"'}

        @custom_token_auth.verify_token
        async def verify_custom_token(token):
            return token == "this-is-the-custom-token!"

        @custom_token_auth.get_user_roles
        async def get_custom_token_role(auth):
            if auth.token == "this-is-the-custom-token!":
                return "foo"
            return

        @app.route("/")
        async def index():
            return "index"

        @app.route("/protected")
        @multi_auth.login_required
        async def auth_route():
            return "access granted:" + str(multi_auth.current_user())

        @app.route("/protected-with-role")
        @multi_auth.login_required(role="foo")
        async def auth_role_route():
            return "role access granted"

        self.app = app
        self.client = app.test_client()

    async def test_multi_auth_prompt(self):
        response = await self.client.get("/protected")
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"],
            'Basic realm="Authentication Required"',
        )

    async def test_multi_auth_login_valid_basic(self):
        creds = base64.b64encode(b"john:hello").decode("utf-8")
        response = await self.client.get(
            "/protected", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.data.decode("utf-8"), "access granted:john")

    async def test_multi_auth_login_invalid_basic(self):
        creds = base64.b64encode(b"john:bye").decode("utf-8")
        response = await self.client.get(
            "/protected", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            await response.headers["WWW-Authenticate"],
            'Basic realm="Authentication Required"',
        )

    async def test_multi_auth_login_valid_token(self):
        response = await self.client.get(
            "/protected",
            headers={"Authorization": "MyToken this-is-the-token!"},
        )
        self.assertEqual(response.data.decode("utf-8"), "access granted:None")

    async def test_multi_auth_login_invalid_token(self):
        response = await self.client.get(
            "/protected",
            headers={"Authorization": "MyToken this-is-not-the-token!"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"], 'MyToken realm="Foo"'
        )

    async def test_multi_auth_login_valid_custom_token(self):
        response = await self.client.get(
            "/protected", headers={"X-Token": "this-is-the-custom-token!"}
        )
        self.assertEqual(response.data.decode("utf-8"), "access granted:None")

    async def test_multi_auth_login_invalid_custom_token(self):
        response = await self.client.get(
            "/protected", headers={"X-Token": "this-is-not-the-token!"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"],
            'Bearer realm="Authentication Required"',
        )

    async def test_multi_auth_login_invalid_scheme(self):
        response = await self.client.get(
            "/protected", headers={"Authorization": "Foo this-is-the-token!"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"],
            'Basic realm="Authentication Required"',
        )

    async def test_multi_malformed_header(self):
        response = await self.client.get(
            "/protected", headers={"Authorization": "token-without-scheme"}
        )
        self.assertEqual(response.status_code, 401)

    async def test_multi_auth_login_valid_basic_role(self):
        creds = base64.b64encode(b"john:hello").decode("utf-8")
        response = await self.client.get(
            "/protected-with-role", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.data.decode("utf-8"), "role access granted")

    async def test_multi_auth_login_valid_token_role(self):
        response = await self.client.get(
            "/protected-with-role",
            headers={"Authorization": "MyToken this-is-the-token!"},
        )
        self.assertEqual(response.data.decode("utf-8"), "role access granted")

    async def test_multi_auth_login_valid_custom_token_role(self):
        response = await self.client.get(
            "/protected-with-role",
            headers={"X-Token": "this-is-the-custom-token!"},
        )
        self.assertEqual(response.data.decode("utf-8"), "role access granted")
