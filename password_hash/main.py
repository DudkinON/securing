from flask import Flask, jsonify, request, url_for, abort, g
from models import user_exist, create_user, get_user

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()


app = Flask(__name__)


@auth.verify_password
def verify_password(username, password):
    user = get_user(username)
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if username is None or password in None:
        abort(400)
    if user_exist(username):
        return jsonify({'message': 'user already exists'}), 200
    user = create_user(username, password)
    return jsonify({'username': user.username}), 201


@app.route('/protected_resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello: %s!' % g.user.username})


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
