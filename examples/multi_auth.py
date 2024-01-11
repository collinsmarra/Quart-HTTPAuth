#!/usr/bin/env python
"""Multiple authentication example

This example demonstrates how to combine two authentication methods using the
"MultiAuth" class.

The root URL for this application can be accessed via basic auth, providing
username and password, or via token auth, providing a bearer JWS token.

This example requires the PyJWT package to be installed.
"""
from time import time
from quart import Quart
from quart_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
import jwt


app = Quart(__name__)
app.config['SECRET_KEY'] = 'top secret!'

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)


users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye")
}

for user in users.keys():
    token = jwt.encode({'username': user, 'exp': int(time()) + 3600},
                       app.config['SECRET_KEY'], algorithm='HS256')
    print('*** token for {}: {}\n'.format(user, token))


@basic_auth.verify_password
def verify_password(username, password):
    if username in users:
        if check_password_hash(users.get(username), password):
            return username


@token_auth.verify_token
def verify_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'],
                          algorithms=['HS256'])
    except:  # noqa: E722
        return False
    if 'username' in data:
        return data['username']


@app.route('/')
@multi_auth.login_required
async def index():
    return "Hello, %s!" % multi_auth.current_user()


if __name__ == '__main__':
    app.run()
