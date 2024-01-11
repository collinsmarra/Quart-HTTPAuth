import base64
from quart import Quart
from src.quart_httpauth import HTTPBasicAuth
import pytest


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    basic_auth_my_realm = HTTPBasicAuth(realm="My Realm")

    @basic_auth_my_realm.get_password
    async def get_basic_password_2(username):
        if username == "john":
            return "johnhello"
        elif username == "susan":
            return "susanbye"
        else:
            return None

    @basic_auth_my_realm.hash_password
    async def basic_auth_my_realm_hash_password(username, password):
        return username + password

    @basic_auth_my_realm.error_handler
    async def basic_auth_my_realm_error():
        return "custom error"

    @app.route("/")
    async def index():
        return "index"

    @app.route("/basic-with-realm")
    @basic_auth_my_realm.login_required
    async def basic_auth_my_realm_route():
        return "basic_auth_my_realm:" + basic_auth_my_realm.username()

    return app


@pytest.mark.asyncio
async def test_basic_auth_prompt(testapp):
    client = testapp.test_client()
    response = await client.get("/basic-with-realm")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'Basic realm="My Realm"'
    # assert await response.text() == "custom error"


@pytest.mark.asyncio
async def test_basic_auth_login_valid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/basic-with-realm", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 200
    response_data = await response.data
    assert "basic_auth_my_realm:john" in response_data.decode("utf-8")


@pytest.mark.asyncio
async def test_basic_auth_login_invalid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:bye").decode("utf-8")
    response = await client.get(
        "/basic-with-realm", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == 'Basic realm="My Realm"'
