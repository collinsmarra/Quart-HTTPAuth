Quart-HTTPAuth
==============

[![Build status](https://github.com/miguelgrinberg/Flask-HTTPAuth/workflows/build/badge.svg)](https://github.com/miguelgrinberg/Flask-HTTPAuth/actions) [![codecov](https://codecov.io/gh/miguelgrinberg/Flask-HTTPAuth/branch/master/graph/badge.svg?token=KeU2002DHo)](https://codecov.io/gh/miguelgrinberg/Flask-HTTPAuth)

Simple extension that provides Basic, Digest and Token HTTP authentication for Quart routes.


Basic authentication example
----------------------------

```python
from quart import Quart
from quart_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Quart(__name__)
auth = HTTPBasicAuth()

users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
@auth.login_required
async def index():
    return "Hello, %s!" % auth.current_user()

if __name__ == '__main__':
    app.run()
```


Digest authentication example
-----------------------------

```python
from quart import Quart
from flask_httpauth import HTTPDigestAuth

app = Quart(__name__)
app.config['SECRET_KEY'] = 'secret key here'
auth = HTTPDigestAuth()

users = {
    "john": "hello",
    "susan": "bye"
}

@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None

@app.route('/')
@auth.login_required
async def index():
    return "Hello, %s!" % auth.username()

if __name__ == '__main__':
    app.run()
```
