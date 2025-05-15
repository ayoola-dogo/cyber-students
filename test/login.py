from api.crypto_utils import hash_password, encrypt_personal_data
from json import dumps
from tornado.escape import json_decode
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest

from api.handlers.login import LoginHandler


class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        cls.my_app = Application([(r'/login', LoginHandler)])
        cls.personal_data = {
            'displayName': 'john_smith',
            'fullName': 'John Smith',
            'address': '435 Highway Street, Maryland',
            'dateOfBirth': '01/05/1983',
            'phoneNumber': '1234567',
            'disabilities': ['Dyslexia', 'Wheelchair User'],
        }
        super().setUpClass()

    @coroutine
    def register(self):
        # Hash the password for testing
        password_data = hash_password(self.password)

        # Encrypt the display name
        user_encrypted_data = encrypt_personal_data(
            dumps(self.personal_data)
        )

        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'personal_data': user_encrypted_data['encrypted_data'],
            'personal_data_iv': user_encrypted_data['nonce'],
            'salt': password_data['salt'],
            'password': password_data['hash']
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
          'email': self.email,
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
          'email': self.email.swapcase(),
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)
