from tornado.web import authenticated

from .auth import AuthHandler


class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['displayName']
        self.response["fullName"] = self.current_user['fullName']
        self.response["address"] = self.current_user['address']
        self.response["dateOfBirth"] = self.current_user['dateOfBirth']
        self.response["phoneNumber"] = self.current_user['phoneNumber']
        self.response["disabilities"] = self.current_user['disabilities']
        self.write_json()
