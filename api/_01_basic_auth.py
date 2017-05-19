# -*- coding: utf-8 -*-

from flask import Flask, request
from .utils import json_response

app = Flask(__name__)


@app.route('/')
def home():
    auth = request.authorization
    return json_response({
        'username': auth.username,
        'password': auth.password,
        'status': 'OK'
    })


@app.errorhandler(404)
def not_found(e):
    return json_response(status=404)
