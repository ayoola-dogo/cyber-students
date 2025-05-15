from api.crypto_utils import hash_password, encrypt_personal_data
from json import dumps
from tornado.escape import json_decode
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler

from .base import BaseTest


class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        cls.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        self.personal_data = {
            'displayName': self.display_name,
            'fullName': self.full_name,
            'address': self.address,
            'dateOfBirth': self.doa,
            'phoneNumber': self.phone_number,
            'disabilities': self.disabilities,
        }

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
        self.display_name = 'testDisplayName'
        self.token = 'testToken'
        self.full_name = 'Test DisplayName'
        self.address = '435 Highway Street, Maryland'
        self.doa = '01/05/1983'
        self.phone_number = '1234567'
        self.disabilities = [
            'Dyslexia',
            'Hearing Impairment',
            'Visual Impairment',
        ]

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])
        self.assertEqual(self.full_name, body_2['fullName'])
        self.assertEqual(self.address, body_2['address'])
        self.assertEqual(self.doa, body_2['dateOfBirth'])
        self.assertEqual(self.phone_number, body_2['phoneNumber'])
        self.assertEqual(self.disabilities, body_2['disabilities'])


    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user')
        self.assertEqual(400, response.code)
