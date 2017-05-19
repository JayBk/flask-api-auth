import os
import json
import sqlite3
import unittest
import jwt
from datetime import datetime, timedelta

from api._02_custom_auth import app as api_app_2
from api._03_jwt_auth import app as api_app_3
from api.custom_auth import sign

PROJECT_HOME = os.path.dirname(os.path.realpath(__file__))

TESTING_DATABASE_NAME = 'test_auth.db'
SCHEMA_FILE_NAME = 'auth-schema.sql'


class BaseDatabaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.APP.config.update({
            'DATABASE_NAME': TESTING_DATABASE_NAME
        })

        cls.db = sqlite3.connect(TESTING_DATABASE_NAME)
        with open(os.path.join(PROJECT_HOME, SCHEMA_FILE_NAME), 'r') as fp:
            schema = fp.read()
            cls.db.executescript(schema)
            cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        os.remove(TESTING_DATABASE_NAME)

    def setUp(self):
        self.app = self.APP.test_client()


class CustomAuthTestCases(BaseDatabaseTestCase):
    APP = api_app_2

    def setUp(self):
        super(CustomAuthTestCases, self).setUp()
        self.public_key = 'mobile_app'
        self.secret_key = '$secret$'

    def test_not_auth_required_get(self):
        # Doesn't need auth
        resp = self.app.get('/book')
        self.assertEqual(resp.status_code, 200)

    def test_auth_required_get_works_correctly(self):
        path = '/book/edit'
        signature, credentials = sign(
            self.public_key, self.secret_key, 'GET', path)
        headers = {
            'X-Signature': signature,
            'X-Credentials': credentials
        }
        resp = self.app.get(path, headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_auth_required_post_works_correctly(self):
        path = '/book'
        signature, credentials = sign(
            self.public_key, self.secret_key, 'POST', path)
        headers = {
            'X-Signature': signature,
            'X-Credentials': credentials
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_auth_required_get_without_sending_headers_fails(self):
        path = '/book/edit'
        resp = self.app.get(path)
        self.assertEqual(resp.status_code, 401)

    def test_auth_required_missing_header_fails(self):
        path = '/book'
        signature, credentials = sign(
            self.public_key, self.secret_key, 'POST', path)
        headers = {
            'X-Credentials': credentials
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_auth_required_wrong_credentials_format_fails(self):
        path = '/book'
        signature, credentials = sign(
            self.public_key, self.secret_key, 'POST', path)
        public_key, ts, algo = credentials.split('.')
        headers = {
            'X-Signature': signature,
            'X-Credentials': "{}.{}".format(public_key, ts)
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 400)
        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {'error': 'Wrong Format for Credentials'})

    def test_auth_required_wrong_timestamp_format_fails(self):
        path = '/book'
        signature, credentials = sign(
            self.public_key, self.secret_key, 'POST', path)

        public_key, ts, algo = credentials.split('.')
        headers = {
            'X-Signature': signature,
            'X-Credentials': "{}.{}.{}".format(public_key, 'INVALID', algo)
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 400)
        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {'error': 'Invalid Timestamp'})

    def test_auth_required_expired_timestamp_fails(self):
        path = '/book'
        # 10 minutes ago, expired
        timestamp = datetime.utcnow() - timedelta(minutes=10)

        signature, credentials = sign(
            self.public_key, self.secret_key, 'POST', path, timestamp)

        headers = {
            'X-Signature': signature,
            'X-Credentials': credentials
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 400)
        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {
            'error': 'Timestamp Expired. Valid for 5 minutes'})

    def test_auth_required_wrong_public_key_fails(self):
        path = '/book'
        signature, credentials = sign(
            'INVALID', self.secret_key, 'POST', path)
        headers = {
            'X-Signature': signature,
            'X-Credentials': credentials
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_auth_required_spoofed_secret_key(self):
        path = '/book'
        signature, credentials = sign(
            self.public_key, '$SPOOFING$', 'POST', path)

        headers = {
            'X-Signature': signature,
            'X-Credentials': credentials
        }
        resp = self.app.post(path, headers=headers)
        self.assertEqual(resp.status_code, 401)


class JWTTestCases(BaseDatabaseTestCase):
    APP = api_app_3

    def setUp(self):
        super(JWTTestCases, self).setUp()
        self.username = 'admin'
        self.password = 'secret'

    def test_login_correct_user(self):
        credentials = json.dumps({
            'username': self.username,
            'password': self.password,
        })
        resp = self.app.post(
            '/login', data=credentials, content_type='application/json')

        self.assertEqual(resp.status_code, 200)

        content = json.loads(resp.get_data(as_text=True))
        self.assertTrue('token'in content)

    def test_login_incorrect_user(self):
        credentials = json.dumps({
            'username': self.username,
            'password': 'INVALID',
        })
        resp = self.app.post(
            '/login', data=credentials, content_type='application/json')
        self.assertEqual(resp.status_code, 400)

        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {
            'error': 'Invalid Credentials'
        })

    def test_not_authenticated_cant_post(self):
        resp = self.app.post('/book')
        self.assertEqual(resp.status_code, 400)

        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {
            'error': 'Authorization header not provided'
        })

    def test_send_invalid_header(self):
        headers = {
            'Authorization': 'Basic ----'
        }
        resp = self.app.post('/book', headers=headers)
        self.assertEqual(resp.status_code, 400)

        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {
            'error': 'Authorization header format error'
        })

    def test_send_incorrect_token(self):
        headers = {
            'Authorization': 'Bearer XXXX.YYYY.ZZZZ'
        }
        resp = self.app.post('/book', headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_send_invalid_secret(self):
        token = jwt.encode({'username': 'admin'}, 'SPOOFED').decode('utf-8')
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }
        resp = self.app.post('/book', headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_authenticated_sends_correct_token(self):
        credentials = json.dumps({
            'username': self.username,
            'password': self.password,
        })
        resp = self.app.post(
            '/login', data=credentials, content_type='application/json')

        self.assertEqual(resp.status_code, 200)

        content = json.loads(resp.get_data(as_text=True))
        self.assertTrue('token'in content)
        token = content['token']

        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }
        resp = self.app.post('/book', headers=headers)
        content = json.loads(resp.get_data(as_text=True))
        self.assertEqual(content, {
            'greetings': 'admin'
        })
