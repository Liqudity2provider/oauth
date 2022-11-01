from rest_framework import serializers
from rest_framework.relations import SlugRelatedField
from rest_framework.serializers import ModelSerializer

from server_part.keys_manager import KeyManager
from server_part.models import Keys, Token
from server_part.utils import to_base64url_uint


class KeysSerializer(ModelSerializer):
    n = serializers.SerializerMethodField('get_n')
    e = serializers.SerializerMethodField('get_e')
    kty = serializers.SerializerMethodField('get_kty')
    use = serializers.SerializerMethodField('get_use')

    def __init__(self, *args, **kwargs):
        self.key_manager = KeyManager
        super(KeysSerializer, self).__init__(*args, **kwargs)

    def get_n(self, _model):
        return to_base64url_uint(self.key_manager.get_n_e(_model.public_key).get("n", ""))

    def get_e(self, _model):
        return to_base64url_uint(self.key_manager.get_n_e(_model.public_key).get("e", ""))

    def get_kty(self, _model):
        return "RSA"

    def get_use(self, _model):
        return "sig"

    class Meta:
        model = Keys
        fields = ["kid", "algorithm", "n", "e", "kty", "use"]


class TokenSerializer(ModelSerializer):
    keys = SlugRelatedField(
        many=True, read_only=True, slug_field='kid'
    )

    class Meta:
        model = Token
        fields = ['keys']
