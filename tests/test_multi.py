import base64
import pytest
from quart import Quart
from src.quart_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    basic_auth = HTTPBasicAuth()
    token_auth = HTTPTokenAuth("MyToken")
    custom_token_auth = HTTPTokenAuth(header="X-Token")
    multi_auth = MultiAuth(basic_auth, token_auth, custom_token_auth)

    @basic_auth.verify_password
    def verify_password(username, password):
        if username == "john" and password == "hello":
            return "john"

    @basic_auth.get_user_roles
    def get_basic_role(username):
        if username == "john":
            return ["foo", "bar"]

    @token_auth.verify_token
    def verify_token(token):
        return token == "this-is-the-token!"

    @token_auth.get_user_roles
    def get_token_role(auth):
        if auth.token == "this-is-the-token!":
            return "foo"
        return

    @token_auth.error_handler
    def error_handler():
        return "error", 401, {"WWW-Authenticate": 'MyToken realm="Foo"'}

    @custom_token_auth.verify_token
    def verify_custom_token(token):
        return token == "this-is-the-custom-token!"

    @custom_token_auth.get_user_roles
    def get_custom_token_role(auth):
        if auth.token == "this-is-the-custom-token!":
            return "foo"
        return

    @app.route("/")
    def index():
        return "index"

    @app.route("/protected")
    @multi_auth.login_required
    def auth_route():
        return "access granted:" + str(multi_auth.current_user())

    @app.route("/protected-with-role")
    @multi_auth.login_required(role="foo")
    async def auth_role_route():
        return "role access granted"

    return app


@pytest.mark.asyncio
async def test_multi_auth_prompt(testapp):
    client = testapp.test_client()
    response = await client.get("/protected")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert (
        response.headers["WWW-Authenticate"]
        == 'Basic realm="Authentication Required"'
    )


@pytest.mark.asyncio
async def test_multi_auth_login_valid_basic(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/protected", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "access granted:john"


@pytest.mark.asyncio
async def test_multi_auth_login_invalid_basic(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:bye").decode("utf-8")
    response = await client.get(
        "/protected", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert (
        response.headers["WWW-Authenticate"]
        == 'Basic realm="Authentication Required"'
    )


@pytest.mark.asyncio
async def test_multi_auth_login_valid_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "MyToken this-is-the-token!"}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "access granted:None"


@pytest.mark.asyncio
async def test_multi_auth_login_invalid_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected",
        headers={"Authorization": "MyToken this-is-not-the-token!"},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'MyToken realm="Foo"'


@pytest.mark.asyncio
async def test_multi_auth_login_valid_custom_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"X-Token": "this-is-the-custom-token!"}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "access granted:None"


@pytest.mark.asyncio
async def test_multi_auth_login_invalid_custom_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"X-Token": "this-is-not-the-token!"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert (
        response.headers["WWW-Authenticate"]
        == 'Bearer realm="Authentication Required"'
    )


@pytest.mark.asyncio
async def test_multi_auth_login_invalid_scheme(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "Foo this-is-the-token!"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert (
        response.headers["WWW-Authenticate"]
        == 'Basic realm="Authentication Required"'
    )


@pytest.mark.asyncio
async def test_multi_malformed_header(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "token-without-scheme"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_multi_auth_login_valid_basic_role(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/protected-with-role", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response.status_code == 200
    assert response_data.decode("utf-8") == "role access granted"


@pytest.mark.asyncio
async def test_multi_auth_login_valid_token_role(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected-with-role",
        headers={"Authorization": "MyToken this-is-the-token!"},
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "role access granted"


@pytest.mark.asyncio
async def test_multi_auth_login_valid_custom_token_role(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected-with-role",
        headers={"X-Token": "this-is-the-custom-token!"},
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "role access granted"
