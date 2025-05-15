from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler
from api.crypto_utils import decrypt_personal_data
from json import loads


class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'personal_data': 1,
            'personal_data_iv': 1,
            'expiresIn': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        # Decrypt user profile details
        # There will always be displayName for all users. Hence, personal_data
        # will always have a value.
        personal_data = decrypt_personal_data(
            {
                'nonce': user.get('personal_data_iv'),
                'encrypted_data': user.get('personal_data')
            }
        )

        self.current_user = {
            'email': user['email'],
            **loads(personal_data),
        }
