import base64
from quart import Quart, g
from src.quart_httpauth import HTTPBasicAuth
import pytest


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    basic_verify_auth = HTTPBasicAuth()

    @basic_verify_auth.verify_password
    async def basic_verify_auth_verify_password(username, password):
        g.anon = False
        if username == "john":
            return password == "hello"
        elif username == "susan":
            return password == "bye"
        elif username == "garçon":
            return password == "áéíóú"
        elif username == "":
            g.anon = True
            return True
        return False

    @basic_verify_auth.error_handler
    async def error_handler():
        assert basic_verify_auth.current_user() is None
        return "error", 403  # use a custom error status

    @app.route("/")
    async def index():
        return "index"

    @app.route("/basic-verify")
    @basic_verify_auth.login_required
    async def basic_verify_auth_route():
        return (
            "basic_verify_auth:"
            + basic_verify_auth.username()
            + " anon:"
            + str(g.anon)
        )

    return app


@pytest.mark.asyncio
async def test_verify_auth_login_valid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"susan:bye").decode()
    response = await client.get(
        "/basic-verify", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"basic_verify_auth:susan anon:False"


@pytest.mark.asyncio
async def test_verify_auth_login_valid_latin1(testapp):
    client = testapp.test_client()
    creds = base64.b64encode("garçon:áéíóú".encode("latin1")).decode()
    response = await client.get(
        "/basic-verify", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data.decode() == "basic_verify_auth:garçon anon:False"


@pytest.mark.asyncio
async def test_verify_auth_login_empty(testapp):
    client = testapp.test_client()
    response = await client.get("/basic-verify")
    response_data = await response.data
    assert response_data == b"basic_verify_auth: anon:True"


@pytest.mark.asyncio
async def test_verify_auth_login_invalid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:bye").decode()
    response = await client.get(
        "/basic-verify", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 403
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_verify_auth_login_malformed_password(testapp):
    client = testapp.test_client()
    creds = "eyJhbGciOieyJp=="
    response = await client.get(
        "/basic-verify", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 403
    assert "WWW-Authenticate" in response.headers
