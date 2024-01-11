import pytest
import re
from hashlib import md5
from quart import Quart
from src.flask_httpauth import HTTPDigestAuth
from werkzeug.http import parse_dict_header


def md5_str(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return md5(s).hexdigest()


def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5_str(a1)


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    digest_auth = HTTPDigestAuth(qop=None)

    @digest_auth.get_password
    def get_digest_password_2(username):
        if username == "susan":
            return "hello"
        elif username == "john":
            return "bye"
        else:
            return None

    @app.route("/")
    def index():
        return "index"

    @app.route("/digest")
    @digest_auth.login_required
    def digest_auth_route():
        return "digest_auth:" + digest_auth.username()

    return app, digest_auth


@pytest.mark.asyncio
async def test_digest_auth_prompt(testapp):
    testapp, _ = testapp
    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert re.match(
        r'^Digest realm="Authentication Required",'
        r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
        response.headers["WWW-Authenticate"],
    )


@pytest.mark.asyncio
async def test_digest_auth_ignore_options(testapp):
    testapp, _ = testapp
    client = testapp.test_client()
    response = await client.options("/digest")
    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.asyncio
async def test_digest_auth_login_valid(testapp):
    testapp, _ = testapp
    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "john:" + d["realm"] + ":bye"
    ha1 = md5_str(a1)
    a2 = "GET:/digest"
    ha2 = md5_str(a2)
    a3 = ha1 + ":" + d["nonce"] + ":" + ha2
    auth_response = md5_str(a3)

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    response_data = await response.data
    assert response_data == b"digest_auth:john"


@pytest.mark.asyncio
async def test_digest_auth_login_bad_realm(testapp):
    client, _ = testapp
    client = client.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "john:" + "Wrong Realm" + ":bye"
    ha1 = md5_str(a1)
    a2 = "GET:/digest"
    ha2 = md5_str(a2)
    a3 = ha1 + ":" + d["nonce"] + ":" + ha2
    auth_response = md5_str(a3)

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert re.match(
        r'^Digest realm="Authentication Required",'
        r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
        response.headers["WWW-Authenticate"],
    )


@pytest.mark.asyncio
async def test_digest_auth_login_invalid2(testapp):
    client, _ = testapp
    client = client.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "david:" + "Authentication Required" + ":bye"
    ha1 = md5_str(a1)
    a2 = "GET:/digest"
    ha2 = md5_str(a2)
    a3 = ha1 + ":" + d["nonce"] + ":" + ha2
    auth_response = md5_str(a3)

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="david",realm="{0}",'
            'nonce="{1}",uri="/digest",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert re.match(
        r'^Digest realm="Authentication Required",'
        r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
        response.headers["WWW-Authenticate"],
    )


@pytest.mark.asyncio
async def test_digest_generate_ha1(testapp):
    _, digest_auth = testapp
    ha1 = digest_auth.generate_ha1("pawel", "test")
    ha1_expected = get_ha1("pawel", "test", digest_auth.realm)
    assert ha1 == ha1_expected


@pytest.mark.asyncio
async def test_digest_custom_nonce_checker(testapp):
    testapp, digest_auth = testapp
    # digest_auth = digest_auth.digest_auth

    @digest_auth.generate_nonce
    def noncemaker():
        return "not a good nonce"

    @digest_auth.generate_opaque
    def opaquemaker():
        return "some opaque"

    verify_nonce_called = []

    @digest_auth.verify_nonce
    def verify_nonce(provided_nonce):
        verify_nonce_called.append(provided_nonce)
        return True

    verify_opaque_called = []

    @digest_auth.verify_opaque
    def verify_opaque(provided_opaque):
        verify_opaque_called.append(provided_opaque)
        return True

    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    assert d["nonce"] == "not a good nonce"
    assert d["opaque"] == "some opaque"

    a1 = "john:" + d["realm"] + ":bye"
    ha1 = md5_str(a1)
    a2 = "GET:/digest"
    ha2 = md5_str(a2)
    a3 = ha1 + ":" + d["nonce"] + ":" + ha2
    auth_response = md5_str(a3)

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    response_data = await response.data
    assert response_data == b"digest_auth:john"
    assert verify_nonce_called == ["not a good nonce"]
    assert verify_opaque_called == ["some opaque"]
