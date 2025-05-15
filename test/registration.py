from json import dumps
from tornado.escape import json_decode
from tornado.web import Application

from api.handlers.registration import RegistrationHandler

from .base import BaseTest


class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        cls.my_app = Application([(r'/registration', RegistrationHandler)])
        super().setUpClass()

    def test_registration(self):
        email = 'test@test.com'
        display_name = 'testDisplayName'
        full_name = 'Test User Full Name'
        address = '123 Test Street, Test City'
        dob = '1990-01-15'
        phone_number = '1234567890'
        disabilities = ['Hearing Impairment', 'Visual Impairment']

        body = {
            'email': email,
            'password': 'testPassword',
            'displayName': display_name,
            'full_name': full_name,
            'address': address,
            'dateOfBirth': dob,
            'phone_number': phone_number,
            'disabilities': disabilities
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(display_name, body_2['displayName'])

    def test_registration_without_display_name(self):
        email = 'test@test.com'

        body = {
          'email': email,
          'password': 'testPassword'
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(email, body_2['displayName'])

    def test_registration_twice(self):
        body = {
          'email': 'test@test.com',
          'password': 'testPassword',
          'displayName': 'testDisplayName'
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)
