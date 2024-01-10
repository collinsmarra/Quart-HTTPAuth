import base64
import sys
import unittest
import pytest

from src.flask_httpauth import HTTPTokenAuth
from quart import Quart
import quart_flask_patch


@pytest.mark.skipif(sys.version_info < (3, 7), reason='requires python3.7')
class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Quart(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        token_auth = HTTPTokenAuth('MyToken')
        token_auth2 = HTTPTokenAuth('Token', realm='foo')
        token_auth3 = HTTPTokenAuth(header='X-API-Key')

        @token_auth.verify_token
        async def verify_token(token):
            if token == 'this-is-the-token!':
                return 'user'

        @token_auth3.verify_token
        async def verify_token3(token):
            if token == 'this-is-the-token!':
                return 'user'

        @token_auth.error_handler
        async def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @app.route('/')
        async def index():
            return 'index'

        @app.route('/protected')
        @token_auth.login_required
        async def token_auth_route():
            return 'token_auth:' + token_auth.current_user()

        @app.route('/protected-optional')
        @token_auth.login_required(optional=True)
        async def token_auth_optional_route():
            return 'token_auth:' + str(token_auth.current_user())

        @app.route('/protected2')
        @token_auth2.login_required
        async def token_auth_route2():
            return 'token_auth2'

        @app.route('/protected3')
        @token_auth3.login_required
        async def token_auth_route3():
            return 'token_auth3:' + token_auth3.current_user()

        self.app = app
        self.token_auth = token_auth
        self.client = app.test_client()

    async def test_token_auth_prompt(self):
        response = await self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    async def test_token_auth_ignore_options(self):
        response = await self.client.options('/protected')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    async def test_token_auth_login_valid(self):
        response = await self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth:user')

    async def test_token_auth_login_valid_different_case(self):
        response = await self.client.get(
            '/protected', headers={'Authorization':
                                   'mytoken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth:user')

    async def test_token_auth_login_optional(self):
        response = await self.client.get('/protected-optional')
        self.assertEqual(response.data.decode('utf-8'), 'token_auth:None')

    async def test_token_auth_login_invalid_token(self):
        response = await self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-not-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    async def test_token_auth_login_invalid_scheme(self):
        response = await self.client.get(
            '/protected', headers={'Authorization': 'Foo this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    async def test_token_auth_login_invalid_header(self):
        response = await self.client.get(
            '/protected', headers={'Authorization': 'this-is-a-bad-header'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    async def test_token_auth_login_invalid_no_callback(self):
        response = await self.client.get(
            '/protected2', headers={'Authorization':
                                    'Token this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Token realm="foo"')

    async def test_token_auth_custom_header_valid_token(self):
        response = await self.client.get(
            '/protected3', headers={'X-API-Key': 'this-is-the-token!'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'token_auth3:user')

    async def test_token_auth_custom_header_invalid_token(self):
        response = await self.client.get(
            '/protected3', headers={'X-API-Key': 'invalid-token-should-fail'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)

    async def test_token_auth_custom_header_invalid_header(self):
        response = await self.client.get(
            '/protected3', headers={'API-Key': 'this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')

    async def test_token_auth_header_precedence(self):
        basic_creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = await self.client.get(
            '/protected3', headers={'Authorization': 'Basic ' + basic_creds,
                                    'X-API-Key': 'this-is-the-token!'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'token_auth3:user')
