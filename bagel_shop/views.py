from models import get_user, user_exist, create_user, get_user_by_id
from models import get_bagels, create_bagel
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from flask_httpauth import HTTPBasicAuth


auth = HTTPBasicAuth()

app = Flask(__name__)


@app.route('/')
def home():
    return "home"


# ADD @auth.verify_password here
@auth.verify_password
def verify_password(username, password):
    user = get_user(username)
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


@app.route('/users/create')
def users_create():
    return render_template('index.html')


# ADD a /users route here
@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if username is None or password is None:
        print "missing arguments"
        abort(400)
    if user_exist(username):
        return jsonify({'message': 'user already exists'}), 200
    user = create_user(username, password)
    return jsonify({'username': user.username}), 201


@app.route('/users/<int:uid>')
def get_user(uid):
    user = get_user_by_id(uid)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


@app.route('/bagels', methods=['GET', 'POST'])
@auth.login_required
# protect this route with a required login
def show_all_bagels():
    if request.method == 'GET':
        bagels = get_bagels()
        return jsonify(bagels=[bagel.serialize for bagel in bagels])
    elif request.method == 'POST':
        name = request.json.get('name')
        description = request.json.get('description')
        picture = request.json.get('picture')
        price = request.json.get('price')
        new_bagel = create_bagel(name=name, description=description,
                                 picture=picture, price=price)

        return jsonify(new_bagel.serialize)


if __name__ == '__main__':
    app.debug = True
    app.run(host='127.0.0.1', port=8000)
