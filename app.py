from flask import Flask, request
from flask_jwt import JWT, jwt_required
import hmac
from common import config
from mos import add_acl_to_client, create_user, delete_acl_from_client, delete_user, get_client_acl, update_password


app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = '5skj9ki%#4d_4f3qv&n+9nl(4y@1%#s3uo)7wro+m4d)e43y7*'


def safe_str_cmp(a, b):
    return hmac.compare_digest(a, b)


class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id


users = [
    User(1, 'admin', 'admin'),
]

username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}


def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user


def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)


jwt = JWT(app, authenticate, identity)


@app.get('/users/<string:username>')
@jwt_required()
def user_detail(username):
    r, w = get_client_acl(username)
    return {
        "read": r,
        "write": w
    }


@app.post('/users')
@jwt_required()
def user_create():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    create_user(username=username, password=password)
    return "ok"


@app.patch('/users/<string:username>')
@jwt_required()
def user_change_password(username):
    data = request.get_json()
    password = data.get("password")
    update_password(username=username, password=password)
    return "ok"


@app.post('/users/<string:username>/acls')
@jwt_required()
def user_add_acl(username):
    data = request.get_json()
    read = data.get("read", [])
    write = data.get("write", [])
    add_acl_to_client(username, read, write)
    return "ok"


@app.delete('/users/<string:username>/acls')
@jwt_required()
def user_delete_acl(username):
    data = request.get_json()
    read = data.get("read", [])
    write = data.get("write", [])
    delete_acl_from_client(username, read, write)
    return "ok"


@app.delete('/users/<string:username>')
@jwt_required()
def user_delete(username):
    delete_user(username)
    return "ok"


if __name__ == '__main__':
    app.run(host=config['app']['host'], port=int(
        config['app']['port']), debug=True)
