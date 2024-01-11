import pytest
import base64
from quart import Quart
from src.flask_httpauth import HTTPTokenAuth


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    token_auth = HTTPTokenAuth("MyToken")
    token_auth2 = HTTPTokenAuth("Token", realm="foo")
    token_auth3 = HTTPTokenAuth(header="X-API-Key")

    @token_auth.verify_token
    def verify_token(token):
        if token == "this-is-the-token!":
            return "user"

    @token_auth3.verify_token
    def verify_token3(token):
        if token == "this-is-the-token!":
            return "user"

    @token_auth.error_handler
    def error_handler():
        return "error", 401, {"WWW-Authenticate": 'MyToken realm="Foo"'}

    @app.route("/")
    def index():
        return "index"

    @app.route("/protected")
    @token_auth.login_required
    def token_auth_route():
        return "token_auth:" + token_auth.current_user()

    @app.route("/protected-optional")
    @token_auth.login_required(optional=True)
    def token_auth_optional_route():
        return "token_auth:" + str(token_auth.current_user())

    @app.route("/protected2")
    @token_auth2.login_required
    def token_auth_route2():
        return "token_auth2"

    @app.route("/protected3")
    @token_auth3.login_required
    def token_auth_route3():
        return "token_auth3:" + token_auth3.current_user()

    return app


@pytest.mark.asyncio
async def test_token_auth_prompt(testapp):
    client = testapp.test_client()
    response = await client.get("/protected")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'MyToken realm="Foo"'


@pytest.mark.asyncio
async def test_token_auth_ignore_options(testapp):
    client = testapp.test_client()
    response = await client.options("/protected")
    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.asyncio
async def test_token_auth_login_valid(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "MyToken this-is-the-token!"}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "token_auth:user"


@pytest.mark.asyncio
async def test_token_auth_login_valid_different_case(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "mytoken this-is-the-token!"}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "token_auth:user"


@pytest.mark.asyncio
async def test_token_auth_login_optional(testapp):
    client = testapp.test_client()
    response = await client.get("/protected-optional")
    response_data = await response.data
    assert response_data.decode("utf-8") == "token_auth:None"


@pytest.mark.asyncio
async def test_token_auth_login_invalid_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected",
        headers={"Authorization": "MyToken this-is-not-the-token!"},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'MyToken realm="Foo"'


@pytest.mark.asyncio
async def test_token_auth_login_invalid_scheme(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "Foo this-is-the-token!"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'MyToken realm="Foo"'


@pytest.mark.asyncio
async def test_token_auth_login_invalid_header(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected", headers={"Authorization": "this-is-a-bad-header"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'MyToken realm="Foo"'


@pytest.mark.asyncio
async def test_token_auth_login_invalid_no_callback(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected2", headers={"Authorization": "Token this-is-the-token!"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'Token realm="foo"'


@pytest.mark.asyncio
async def test_token_auth_custom_header_valid_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected3", headers={"X-API-Key": "this-is-the-token!"}
    )
    assert response.status_code == 200
    response_data = await response.data
    assert response_data.decode("utf-8") == "token_auth3:user"


@pytest.mark.asyncio
async def test_token_auth_custom_header_invalid_token(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected3", headers={"X-API-Key": "invalid-token-should-fail"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_token_auth_custom_header_invalid_header(testapp):
    client = testapp.test_client()
    response = await client.get(
        "/protected3", headers={"API-Key": "this-is-the-token!"}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert (
        response.headers["WWW-Authenticate"]
        == 'Bearer realm="Authentication Required"'
    )


@pytest.mark.asyncio
async def test_token_auth_header_precedence(testapp):
    client = testapp.test_client()
    basic_creds = base64.b64encode(b"susan:bye").decode("utf-8")
    response = await client.get(
        "/protected3",
        headers={
            "Authorization": "Basic " + basic_creds,
            "X-API-Key": "this-is-the-token!",
        },
    )
    assert response.status_code == 200
    response_data = await response.data
    assert response_data.decode("utf-8") == "token_auth3:user"
