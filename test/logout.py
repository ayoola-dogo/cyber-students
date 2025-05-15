from api.crypto_utils import hash_password, encrypt_personal_data
from json import dumps
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.logout import LogoutHandler

from .base import BaseTest


class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        cls.my_app = Application([(r'/logout', LogoutHandler)])
        cls.personal_data = {
            'displayName': 'john_smith',
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

    @coroutine
    def login(self):
        yield self.get_app().db.users.update_one({
            'email': self.email
        }, {
            '$set': { 'token': self.token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        # Verify that the token has been cleared after logout
        user = IOLoop.current().run_sync(
            lambda: self.get_app().db.users.find_one({"email": self.email})
        )
        self.assertIsNone(user.get("token"))

    def test_logout_without_token(self):
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(403, response_2.code)
