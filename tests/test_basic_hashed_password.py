import base64
from hashlib import md5 as basic_md5
from quart import Quart
from src.quart_httpauth import HTTPBasicAuth
import pytest


def md5(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return basic_md5(s)


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    basic_custom_auth = HTTPBasicAuth()

    @basic_custom_auth.get_password
    async def get_basic_custom_auth_get_password(username):
        if username == "john":
            return md5("hello").hexdigest()
        elif username == "susan":
            return md5("bye").hexdigest()
        else:
            return None

    @basic_custom_auth.hash_password
    async def basic_custom_auth_hash_password(password):
        return md5(password).hexdigest()

    @app.route("/")
    async def index():
        return "index"

    @app.route("/basic-custom")
    @basic_custom_auth.login_required
    async def basic_custom_auth_route():
        return "basic_custom_auth:" + basic_custom_auth.username()

    return app


@pytest.mark.asyncio
async def test_basic_auth_login_valid_with_hash1(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/basic-custom", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data.decode("utf-8") == "basic_custom_auth:john"


@pytest.mark.asyncio
async def test_basic_custom_auth_login_valid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/basic-custom", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"basic_custom_auth:john"


@pytest.mark.asyncio
async def test_basic_custom_auth_login_invalid(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:bye").decode("utf-8")
    response = await client.get(
        "/basic-custom", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
