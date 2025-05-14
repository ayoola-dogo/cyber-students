from api.crypto_utils import (
    decrypt_personal_data,
    encrypt_personal_data,
    hash_password,
    verify_password,
)
import dateparser
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)

            # email
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()

            # password
            password = body['password']
            if not isinstance(password, str):
                raise Exception()

            # display name
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        # Optional Personal Data
        try:
            # full name
            full_name = body.get("fullName")
            if full_name is not None and (
                not isinstance(full_name, str) or not full_name.strip()
            ):
                raise Exception("The full name is invalid")

            # address
            address = body.get("address")
            if address is not None and (
                not isinstance(address, str) or not address.strip()
            ):
                raise Exception("The address is invalid")

            # dob
            dob = body.get("dateOfBirth")
            if dob is not None and (
                not isinstance(dob, str) or not dateparser.parse(dob)
            ):
                raise Exception(
                    "The date of birth is invalid"
                )

            # Phone number
            phone_number = body.get("phoneNumber")
            if phone_number is not None and (
                not isinstance(phone_number, str) or len(phone_number) < 6
            ):
                raise Exception("Phone number is invalid or too short")

            # disabilities
            disabilities = body.get("disabilities", [])
            if disabilities != [] and (
                not isinstance(disabilities, list) or not all(
                    isinstance(item, str) for item in disabilities
                )
            ):
                raise Exception(
                    "Please provide disabilities as a list of strings")
        except Exception as e:
            self.send_error(400, message=str(e))
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Hash password
        hashed_password = hash_password(password)

        # Encrypt the personal data fields
        encrypted_email = encrypt_personal_data(email)
        encrypted_display_name = encrypt_personal_data(display_name)
        encrypted_full_name = encrypt_personal_data(full_name)
        encrypted_address = encrypt_personal_data(address)
        encrypted_dob = encrypt_personal_data(dob)
        encrypted_phone_number = encrypt_personal_data(phone_number)
        # Convert disabilities list to JSON string before encrypting
        disabilities_json = (
            dumps(disabilities) if len(disabilities) >= 1 else dumps([])
        )
        encrypted_disabilities = encrypt_personal_data(disabilities_json)

        user_doc = {
            "email_iv": encrypted_email["nonce"],
            "email": encrypted_email["encrypted_data"],
            "password_salt": hashed_password["salt"],
            "password": hashed_password["hash"],
            "displayName_iv": encrypted_display_name["nonce"],
            "displayName": encrypted_display_name["encrypted_data"],
            "fullName_iv": encrypted_full_name["nonce"],
            "fullName": encrypted_full_name["encrypted_data"],
            "address_iv": encrypted_address["nonce"],
            "address": encrypted_address["encrypted_data"],
            "dob_iv": encrypted_dob["nonce"],
            "dob": encrypted_dob["encrypted_data"],
            "phoneNumber_iv": encrypted_phone_number["nonce"],
            "phoneNumber": encrypted_phone_number["encrypted_data"],
            "disabilities_iv": encrypted_disabilities["nonce"],
            "disabilities": encrypted_disabilities["encrypted_data"],
        }

        yield self.db.users.insert_one(user_doc)

        self.set_status(200)
        # Return only non-sensitive data
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
