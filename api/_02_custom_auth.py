# -*- coding: utf-8 -*-
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, request, abort, g

from .utils import json_response, error_response
from .custom_auth import parse_datetime_iso, sign

app = Flask(__name__)

MAX_TIMESTAMP_DELTA_IN_MINUTES = 5


@app.before_request
def before_request():
    g.db = sqlite3.connect(app.config['DATABASE_NAME'])


def find_client_secret(public_key):
    query = ("SELECT secret_key FROM "
             "ApiClient a WHERE a.public_key = :public_key")

    cursor = g.db.execute(query, {'public_key': public_key})
    res = cursor.fetchone()

    return res and res[0]


def is_timestamp_fresh(ts):
    td = datetime.utcnow() - ts
    return (td.seconds / 60) < MAX_TIMESTAMP_DELTA_IN_MINUTES


def custom_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract headers
        headers = request.headers

        # Check if all required headers are present
        if not all(['X-Signature' in headers, 'X-Credentials' in headers]):
            abort(401)

        # Extract signature and credentials
        signature, credentials = tuple([
            headers[h] for h in ('X-Signature', 'X-Credentials')])

        # Check if credentials has correct format and extract its parts
        try:
            public_key, ts, algo = credentials.split('.')
        except ValueError:
            return error_response('Wrong Format for Credentials')

        # Check if exists a client with that public key
        secret_key = find_client_secret(public_key)
        if not secret_key:
            abort(401)

        # Parse datetime and check its format
        try:
            timestamp = parse_datetime_iso(ts)
        except ValueError:
            return error_response('Invalid Timestamp')

        # Signatures are valid for only for 5 minutes
        if not is_timestamp_fresh(timestamp):
            return error_response(
                'Timestamp Expired. Valid for {} minutes'.format(
                    MAX_TIMESTAMP_DELTA_IN_MINUTES))

        # Sign the currnet request
        digest, _ = sign(public_key, secret_key, request.method,
                         request.path, timestamp)

        # If signature doesn't match, the secret key is probably spoofed
        if digest != signature:
            abort(401)

        # Public Key available for the request
        g.public_key = public_key

        # Execute original view
        return f(*args, **kwargs)
    return decorated


@app.route('/book')
def get_books():
    return json_response()


@app.route('/book', methods=['POST'])
@custom_auth_required
def create_book():
    return json_response()


@app.route('/book/edit')
@custom_auth_required
def edit_books():
    return json_response()


@app.errorhandler(404)
def not_found(e):
    return json_response(status=404)
