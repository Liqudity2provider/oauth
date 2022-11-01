import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class ManagePasswordForKeys:
    @classmethod
    def create_password(cls, password_length=13):
        return bytes(secrets.token_urlsafe(password_length))


class KeyManager:
    def __init__(self):
        self.e = 65537
        self.algorithm = "RS256"

    def create_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=self.e,
            key_size=2048
        )

        # private_key_pass = ManagePasswordForKeys.create_password()

        # encrypted_pem_private_key = private_key.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.PKCS8,
        #     encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
        # )

        # print(encrypted_pem_private_key)
        # b'-----BEGIN ENCRYPTED PRIVATE KEY-----'

        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # print(pem_public_key)
        # b'-----BEGIN PUBLIC KEY-----'

        unencrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # print(unencrypted_pem_private_key)
        return pem_public_key, unencrypted_pem_private_key, self.algorithm

    @classmethod
    def get_n_e(cls, publ_key):
        pubkey2 = serialization.load_pem_public_key(
            publ_key.encode('ascii'),
            backend=default_backend()
        )

        return {
            "n": pubkey2.public_numbers().n,
            "e": pubkey2.public_numbers().e
        }
