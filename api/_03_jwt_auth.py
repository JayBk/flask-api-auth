# -*- coding: utf-8 -*-
import os
import sqlite3
from datetime import datetime
from functools import wraps

import jwt
from flask import Flask, request, abort, g

from .utils import json_response, error_response

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '$SECRET$')


@app.before_request
def before_request():
    g.db = sqlite3.connect(app.config['DATABASE_NAME'])


def authenticate_user(username, password):
    query = ("SELECT * FROM "
             "User u WHERE u.username = :username AND "
             "u.password = :password;")

    cursor = g.db.execute(query, {'username': username, 'password': password})
    res = cursor.fetchone()

    return res and res[0]


@app.route('/login', methods=['POST'])
def login():
    data = request.json

    if not all(['username' in data, 'password' in data]):
        return error_response('Missing username or password')
    username, password = [data[f] for f in ('username', 'password')]
    user = authenticate_user(username, password)
    if not user:
        return error_response('Invalid Credentials')

    token = jwt.encode({'username': username}, app.config['SECRET_KEY'])

    return json_response({'token': token.decode('utf-8')})


def jwt_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract headers
        headers = request.headers
        if 'Authorization' not in headers:
            return error_response('Authorization header not provided')

        authorization = request.headers['Authorization']
        if not authorization.startswith('Bearer '):
            return error_response('Authorization header format error')

        _, token = authorization.split('Bearer ')
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'])
        except jwt.exceptions.DecodeError:
            abort(401)

        # Make username available to the view
        g.username = decoded['username']

        # Execute original view
        return f(*args, **kwargs)
    return decorated


@app.route('/book', methods=['POST'])
@jwt_auth_required
def create_book():
    return json_response({
        'greetings': g.username
    })


@app.errorhandler(404)
def not_found(e):
    return json_response(status=404)
