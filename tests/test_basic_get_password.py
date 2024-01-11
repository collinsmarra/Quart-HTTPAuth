import base64
from quart import Quart
from src.quart_httpauth import HTTPBasicAuth
import pytest


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    basic_auth = HTTPBasicAuth()

    @basic_auth.get_password
    async def get_basic_password(username):
        if username == "john":
            return "hello"
        elif username == "susan":
            return "bye"
        else:
            return None

    @app.route("/")
    async def index():
        return "index"

    @app.route("/basic")
    @basic_auth.login_required
    async def basic_auth_route():
        return "basic_auth:" + basic_auth.username()

    return app


@pytest.mark.asyncio
async def test_no_auth(testapp):
    client = testapp.test_client()
    response = await client.get("/")
    response_data = await response.data
    assert response_data.decode("utf-8") == "index"


@pytest.mark.asyncio
async def test_basic_auth_prompt(testapp):
    client = testapp.test_client()
    response = await client.get("/basic")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == \
        'Basic realm="Authentication Required"'


@pytest.mark.asyncio
async def test_basic_auth_ignore_options(testapp):
    client = testapp.test_client()
    response = await client.options("/basic")
    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.asyncio
async def test_basic_auth_login_valid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/basic", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "basic_auth:john"


@pytest.mark.asyncio
async def test_basic_auth_login_invalid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:bye").decode("utf-8")
    response = await client.get(
        "/basic", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] ==\
        'Basic realm="Authentication Required"'
