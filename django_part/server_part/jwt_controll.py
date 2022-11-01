import datetime

import jwt

from django_oauth2.settings import ACCESS_TOKEN_EXPIRE_MINUTES
from server_part.keys_manager import KeyManager
from server_part.models import Keys


class JWTManager:
    def __init__(self, algorithm=None, private_key=None, public_key=None):
        self.key_manager = KeyManager()
        if algorithm and private_key and public_key:
            self.algorithm = algorithm
            self.private_key = private_key
            self.public_key = public_key
        else:
            self.keys = self.create_keys()
            self.algorithm = self.keys.algorithm
            self.private_key = self.keys.private_key
            self.public_key = self.keys.public_key

    def create_keys(self):
        """Create Keys model"""
        public_key, private_key, algorithm = self.key_manager.create_keys()
        import random
        import string

        kid = ''.join(random.sample(string.ascii_letters, 20))

        public_key, private_key = public_key.decode("utf-8"), private_key.decode("utf-8")

        return Keys(kid=kid, public_key=public_key, private_key=private_key, algorithm=algorithm)

    def encode_token(self, headers, payload):
        encoded = jwt.encode(payload=payload,
                             key=self.private_key,
                             algorithm=self.algorithm,
                             headers=headers
                             )

        return encoded

    def decode_token(self, token, publ_key):
        try:
            decoded = jwt.decode(token, publ_key, algorithms=[self.algorithm])
            return decoded
        except ValueError:
            print("check public and private keys")

    def create_decoded(self, client_id, time_now, code=None, username=None):
        access_exp = time_now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        decoded_token = {'exp': access_exp.timestamp(),
                         'nbf': time_now.timestamp(),  # could be processed not before
                         # 'ver': '1.0',
                         'iss': client_id,
                         'nonce': code.nonce if code else None,
                         'iat': time_now.timestamp(),
                         'auth_time': time_now.timestamp(),
                         'user_name': username,
                         }
        return decoded_token
