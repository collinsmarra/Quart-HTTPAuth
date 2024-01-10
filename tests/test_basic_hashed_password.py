import unittest
import base64
import quart_flask_patch
from hashlib import md5 as basic_md5
from quart import Quart
from src.flask_httpauth import HTTPBasicAuth


def md5(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return basic_md5(s)


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Quart(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_custom_auth = HTTPBasicAuth()

        @basic_custom_auth.get_password
        async def get_basic_custom_auth_get_password(username):
            if username == 'john':
                return md5('hello').hexdigest()
            elif username == 'susan':
                return md5('bye').hexdigest()
            else:
                return None

        @basic_custom_auth.hash_password
        async def basic_custom_auth_hash_password(password):
            return md5(password).hexdigest()

        @app.route('/')
        def index():
            return 'index'

        @app.route('/basic-custom')
        @basic_custom_auth.login_required
        async def basic_custom_auth_route():
            return 'basic_custom_auth:' + basic_custom_auth.username()

        self.app = app
        self.basic_custom_auth = basic_custom_auth
        self.client = app.test_client()

    async def test_basic_auth_login_valid_with_hash1(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = await self.client.get(
            '/basic-custom', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'),
                         'basic_custom_auth:john')

    async def test_basic_custom_auth_login_valid(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = await self.client.get(
            '/basic-custom', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_custom_auth:john')

    async def test_basic_custom_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = await self.client.get(
            '/basic-custom', headers={"Authorization": "Basic " + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
