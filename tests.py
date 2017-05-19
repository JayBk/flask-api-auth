import os
import json
import sqlite3
import unittest
from datetime import datetime, timedelta

from api._02_custom_auth import app as api_app_2
from api.custom_auth import sign

PROJECT_HOME = os.path.dirname(os.path.realpath(__file__))

TESTING_DATABASE_NAME = 'test_auth.db'
SCHEMA_FILE_NAME = 'auth-schema.sql'


class BaseDatabaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api_app_2.config.update({
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
