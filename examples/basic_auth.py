#!/usr/bin/env python
"""Basic authentication example

This example demonstrates how to protect Quart endpoints with basic
authentication, using secure hashed passwords.

After running this example, visit http://localhost:5000 in your browser. To
gain access, you can use (username=john, password=hello) or
(username=susan, password=bye).
"""
from quart import Quart
from quart_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Quart(__name__)
auth = HTTPBasicAuth()

users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye"),
}


@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(
        users.get(username), password
    ):
        return username


@app.route("/")
@auth.login_required
async def index():
    return "Hello, %s!" % auth.current_user()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
