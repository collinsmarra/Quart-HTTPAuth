import base64
import pytest
from quart import Quart, g
from src.quart_httpauth import HTTPBasicAuth


@pytest.fixture(name="testapp")
def create_app():
    app = Quart(__name__)
    app.config["TESTING"] = True

    roles_auth = HTTPBasicAuth()

    @roles_auth.verify_password
    def roles_auth_verify_password(username, password):
        g.anon = False
        if username == "john":
            return password == "hello"
        elif username == "susan":
            return password == "bye"
        elif username == "cindy":
            return password == "byebye"
        elif username == "":
            g.anon = True
            return True
        return False

    @roles_auth.get_user_roles
    def get_user_roles(auth):
        username = auth.username
        if username == "john":
            return "normal"
        elif username == "susan":
            return ("normal", "special")
        elif username == "cindy":
            return None

    @roles_auth.error_handler
    def error_handler():
        return "error", 403  # use a custom error status

    @app.route("/")
    async def index():
        return "index"

    @app.route("/normal")
    @roles_auth.login_required(role="normal")
    async def roles_auth_route_normal():
        return "normal:" + roles_auth.username()

    @app.route("/special")
    @roles_auth.login_required(role="special")
    async def roles_auth_route_special():
        return "special:" + roles_auth.username()

    @app.route("/normal-or-special")
    @roles_auth.login_required(role=("normal", "special"))
    async def roles_auth_route_normal_or_special():
        return "normal_or_special:" + roles_auth.username()

    @app.route("/normal-and-special")
    @roles_auth.login_required(role=(("normal", "special"),))
    async def roles_auth_route_normal_and_special():
        return "normal_and_special:" + roles_auth.username()

    return app


@pytest.mark.asyncio
async def test_verify_roles_valid_normal_1(testapp):
    creds = base64.b64encode(b"susan:bye").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"normal:susan"


@pytest.mark.asyncio
async def test_verify_roles_valid_normal_2(testapp):
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal", headers={"Authorization": "Basic " + creds}
    )

    response_data = await response.data
    assert response_data == b"normal:john"


@pytest.mark.asyncio
async def test_verify_auth_login_valid_special(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"susan:bye").decode("utf-8")
    response = await client.get(
        "/special", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"special:susan"


@pytest.mark.asyncio
async def test_verify_auth_login_invalid_special_1(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    response = await client.get(
        "/special", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 403
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_verify_auth_login_invalid_special_2(testapp):
    client = testapp.test_client()
    creds = base64.b64encode(b"cindy:byebye").decode("utf-8")
    response = await client.get(
        "/special", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 403
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_verify_auth_login_valid_normal_or_special_1(testapp):
    creds = base64.b64encode(b"susan:bye").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal-or-special", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"normal_or_special:susan"


@pytest.mark.asyncio
async def test_verify_auth_login_valid_normal_or_special_2(testapp):
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal-or-special", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"normal_or_special:john"


@pytest.mark.asyncio
async def test_verify_auth_login_valid_normal_and_special_1(testapp):
    creds = base64.b64encode(b"susan:bye").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal-and-special", headers={"Authorization": "Basic " + creds}
    )
    response_data = await response.data
    assert response_data == b"normal_and_special:susan"


@pytest.mark.asyncio
async def test_verify_auth_login_valid_normal_and_special_2(testapp):
    creds = base64.b64encode(b"john:hello").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal-and-special", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 403
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_verify_auth_login_invalid_password(testapp):
    creds = base64.b64encode(b"john:bye").decode("utf-8")
    client = testapp.test_client()
    response = await client.get(
        "/normal", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 403
    assert "WWW-Authenticate" in response.headers
