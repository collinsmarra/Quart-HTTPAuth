import pytest
from hashlib import md5 as basic_md5
import re
from quart import Quart
from src.quart_httpauth import HTTPDigestAuth
from werkzeug.http import parse_dict_header


def md5(str):
    if type(str).__name__ == "str":
        str = str.encode("utf-8")
    return basic_md5(str)


def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5(a1.encode("utf-8")).hexdigest()


@pytest.fixture(name="testapp")
def app():
    app = Quart(__name__)
    app.config["SECRET_KEY"] = "my secret"

    digest_auth = HTTPDigestAuth()

    @digest_auth.get_password
    async def get_digest_password_2(username):
        if username == "susan":
            return "hello"
        elif username == "john":
            return "bye"
        else:
            return None

    @app.route("/")
    async def index():
        return "index"

    @app.route("/digest")
    @digest_auth.login_required
    async def digest_auth_route():
        return "digest_auth:" + digest_auth.username()

    return app, digest_auth


@pytest.mark.asyncio
async def test_constructor(testapp):
    d = HTTPDigestAuth()
    assert d.qop == ["auth"]
    assert d.algorithm == "MD5"
    d = HTTPDigestAuth(qop=None)
    assert d.qop is None
    d = HTTPDigestAuth(qop="auth")
    assert d.qop == ["auth"]
    d = HTTPDigestAuth(qop=["foo", "bar"])
    assert d.qop == ["foo", "bar"]
    d = HTTPDigestAuth(qop="foo,bar, baz")
    assert d.qop == ["foo", "bar", "baz"]
    d = HTTPDigestAuth(algorithm="md5")
    assert d.algorithm == "MD5"
    d = HTTPDigestAuth(algorithm="md5-sess")
    assert d.algorithm == "MD5-Sess"
    with pytest.raises(ValueError):
        HTTPDigestAuth(algorithm="foo")


@pytest.mark.asyncio
async def test_digest_auth_prompt(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert re.match(
        r'^Digest realm="Authentication Required",'
        r'nonce="[0-9a-f]+",opaque="[0-9a-f]+",'
        r'algorithm="MD5",qop="auth"$',
        response.headers["WWW-Authenticate"],
    )


@pytest.mark.asyncio
async def test_digest_auth_ignore_options(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()
    response = await client.options("/digest")
    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.asyncio
async def test_digest_auth_login_valid(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "john:" + d["realm"] + ":bye"
    ha1 = md5(a1.encode("utf-8")).hexdigest()
    a2 = "GET:/digest"
    ha2 = md5(a2.encode("utf-8")).hexdigest()
    a3 = ha1 + ":" + d["nonce"] + ":00000001:foobar:auth:" + ha2
    auth_response = basic_md5(a3.encode()).hexdigest()

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",qop=auth,'
            'nc=00000001,cnonce="foobar",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    response_data = await response.data
    assert response_data == b"digest_auth:john"


@pytest.mark.asyncio
async def test_digest_auth_md5_sess_login_valid(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()
    digest_auth.algorithm = "MD5-Sess"

    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "john:" + d["realm"] + ":bye"
    ha1 = md5(
        md5(a1.encode("utf-8")).hexdigest() + ":" + d["nonce"] + ":foobar"
    ).hexdigest()
    a2 = "GET:/digest"
    ha2 = md5(a2.encode("utf-8")).hexdigest()
    a3 = ha1 + ":" + d["nonce"] + ":00000001:foobar:auth:" + ha2
    auth_response = md5(a3.encode("utf-8")).hexdigest()

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",qop=auth,'
            'nc=00000001,cnonce="foobar",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    response_data = await response.data
    assert response_data == b"digest_auth:john"


@pytest.mark.asyncio
async def test_digest_auth_login_bad_realm(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "john:" + "Wrong Realm" + ":bye"
    ha1 = md5(a1.encode("utf-8")).hexdigest()
    a2 = "GET:/digest"
    ha2 = md5(a2.encode("utf-8")).hexdigest()
    a3 = ha1 + ":" + d["nonce"] + ":00000001:foobar:auth:" + ha2
    auth_response = md5(a3.encode("utf-8")).hexdigest()

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",qop=auth,'
            'nc=00000001,cnonce="foobar",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert re.match(
        r'^Digest realm="Authentication Required",'
        r'nonce="[0-9a-f]+",opaque="[0-9a-f]+",'
        r'algorithm="MD5",qop="auth"$',
        response.headers["WWW-Authenticate"],
    )


@pytest.mark.asyncio
async def test_digest_auth_login_invalid2(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()
    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    a1 = "david:" + "Authentication Required" + ":bye"
    ha1 = md5(a1.encode("utf-8")).hexdigest()
    a2 = "GET:/digest"
    ha2 = md5(a2.encode("utf-8")).hexdigest()
    a3 = ha1 + ":" + d["nonce"] + ":00000001:foobar:auth:" + ha2
    auth_response = md5(a3.encode("utf-8")).hexdigest()

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",qop=auth,'
            'nc=00000001,cnonce="foobar",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert re.match(
        r'^Digest realm="Authentication Required",'
        r'nonce="[0-9a-f]+",opaque="[0-9a-f]+",'
        r'algorithm="MD5",qop="auth"$',
        response.headers["WWW-Authenticate"],
    )


@pytest.mark.asyncio
async def test_digest_generate_ha1(testapp):
    testapp, digest_auth = testapp
    ha1 = digest_auth.generate_ha1("pawel", "test")
    ha1_expected = get_ha1("pawel", "test", digest_auth.realm)
    assert ha1 == ha1_expected


@pytest.mark.asyncio
async def test_digest_custom_nonce_checker(testapp):
    testapp, digest_auth = testapp
    client = testapp.test_client()

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

    response = await client.get("/digest")
    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate")
    auth_type, auth_info = header.split(None, 1)
    d = parse_dict_header(auth_info)

    assert d["nonce"] == "not a good nonce"
    assert d["opaque"] == "some opaque"

    a1 = "john:" + d["realm"] + ":bye"
    ha1 = md5(a1.encode("utf-8")).hexdigest()
    a2 = "GET:/digest"
    ha2 = md5(a2.encode("utf-8")).hexdigest()
    a3 = ha1 + ":" + d["nonce"] + ":00000001:foobar:auth:" + ha2
    auth_response = md5(a3.encode("utf-8")).hexdigest()

    response = await client.get(
        "/digest",
        headers={
            "Authorization": 'Digest username="john",realm="{0}",'
            'nonce="{1}",uri="/digest",qop=auth,'
            'nc=00000001,cnonce="foobar",response="{2}",'
            'opaque="{3}"'.format(
                d["realm"], d["nonce"], auth_response, d["opaque"]
            )
        },
    )
    response_data = await response.data
    assert response_data == b"digest_auth:john"
    assert verify_nonce_called == ["not a good nonce"]
    assert verify_opaque_called == ["some opaque"]
