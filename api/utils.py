import json
from flask import make_response

JSON_MIME_TYPE = 'application/json'


def search_book(books, book_id):
    for book in books:
        if book['id'] == book_id:
            return book


def json_response(data=None, status=200, headers=None):
    data = data or {}
    headers = headers or {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = JSON_MIME_TYPE

    return make_response(json.dumps(data), status, headers)


def error_response(error, status=400, headers=None):
    return json_response({'error': error}, status, headers)
