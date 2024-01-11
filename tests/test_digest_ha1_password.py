import pytest
from hashlib import md5
from quart import Quart
from src.quart_httpauth import HTTPDigestAuth
from werkzeug.http import parse_dict_header


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    digest_auth_ha1_pw = HTTPDigestAuth(use_ha1_pw=True)

    @digest_auth_ha1_pw.get_password
    async def get_digest_password(username):
        if username == "susan":
            return get_ha1(username, "hello", digest_auth_ha1_pw.realm)
        elif username == "john":
            return get_ha1(username, "bye", digest_auth_ha1_pw.realm)
        else:
            return None

    @app.route("/")
    async def index():
        return "index"

    @app.route("/digest_ha1_pw")
    @digest_auth_ha1_pw.login_required
    async def digest_auth_ha1_pw_route():
        return "digest_auth_ha1_pw:" + digest_auth_ha1_pw.username()

    return app


def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5(a1.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_digest_ha1_pw_auth_login_valid(testapp):
    client = testapp.test_client()
    response = await client.get("/digest_ha1_pw")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "john:" + d["realm"] + ":bye"
    ha1 = md5(a1.encode("utf-8")).hexdigest()
    a2 = "GET:/digest_ha1_pw"
    ha2 = md5(a2.encode("utf-8")).hexdigest()
    a3 = ha1 + ":" + d["nonce"] + ":" + ha2
    auth_response = md5(a3.encode("utf-8")).hexdigest()

    response = await client.get(
        "/digest_ha1_pw",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest_ha1_pw",'
            'response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            ),
        },
    )
    response_data = await response.data
    assert response_data == b"digest_auth_ha1_pw:john"
