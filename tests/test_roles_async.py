import sys
import unittest
import base64
import pytest

from quart import Quart, g
import quart_flask_patch
from src.flask_httpauth import HTTPBasicAuth

@pytest.mark.skipif(sys.version_info < (3, 7), reason='requires python3.7')
class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Quart(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        roles_auth = HTTPBasicAuth()

        @roles_auth.verify_password
        async def roles_auth_verify_password(username, password):
            g.anon = False
            if username == 'john':
                return password == 'hello'
            elif username == 'susan':
                return password == 'bye'
            elif username == 'cindy':
                return password == 'byebye'
            elif username == '':
                g.anon = True
                return True
            return False

        @roles_auth.get_user_roles
        async def get_user_roles(auth):
            username = auth.username
            if username == 'john':
                return 'normal'
            elif username == 'susan':
                return ('normal', 'special')
            elif username == 'cindy':
                return None

        @roles_auth.error_handler
        async def error_handler():
            return 'error', 403  # use a custom error status

        @app.route('/')
        async def index():
            return 'index'

        @app.route('/normal')
        @roles_auth.login_required(role='normal')
        async def roles_auth_route_normal():
            return 'normal:' + roles_auth.username()

        @app.route('/special')
        @roles_auth.login_required(role='special')
        async def roles_auth_route_special():
            return 'special:' + roles_auth.username()

        @app.route('/normal-or-special')
        @roles_auth.login_required(role=('normal', 'special'))
        async def roles_auth_route_normal_or_special():
            return 'normal_or_special:' + roles_auth.username()

        @app.route('/normal-and-special')
        @roles_auth.login_required(role=(('normal', 'special'),))
        async def roles_auth_route_normal_and_special():
            return 'normal_and_special:' + roles_auth.username()

        self.app = app
        self.roles_auth = roles_auth
        self.client = app.test_client()

    async def test_verify_roles_valid_normal_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = await self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal:susan')

    async def test_verify_roles_valid_normal_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = await self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal:john')

    async def test_verify_auth_login_valid_special(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = await self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'special:susan')

    async def test_verify_auth_login_invalid_special_1(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = await self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    async def test_verify_auth_login_invalid_special_2(self):
        creds = base64.b64encode(b'cindy:byebye').decode('utf-8')
        response = await self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    async def test_verify_auth_login_valid_normal_or_special_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = await self.client.get(
            '/normal-or-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal_or_special:susan')

    async def test_verify_auth_login_valid_normal_or_special_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = await self.client.get(
            '/normal-or-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal_or_special:john')

    async def test_verify_auth_login_valid_normal_and_special_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = await self.client.get(
            '/normal-and-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal_and_special:susan')

    async def test_verify_auth_login_valid_normal_and_special_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = await self.client.get(
            '/normal-and-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    async def test_verify_auth_login_invalid_password(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = await self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)
