from oauthlib.oauth2 import RequestValidator

from server_part.models import Client


class CustomRequestValidator(RequestValidator):
    """
    client_id needs to be specified in param of request
    """

    def validate_client_id(self, client_id, request, *args, **kwargs) -> Client:
        try:
            return Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            raise Client.DoesNotExist

    def authenticate_client(self, request, *args, **kwargs):
        client_id = request.query_params.get("client_id")
        try:
            client = Client.objects.get(client_id=client_id)
            request.client = client
            return True
        except Client.DoesNotExist:
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        try:
            client = Client.objects.get(client_id=client_id)
            request.client = client
            return True
        except Client.DoesNotExist:
            return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request,
                             *args, **kwargs):
        """Verify that code attached to the client"""
        assert code == client.code
        assert redirect_uri == client.redirect_uri
        return True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        try:
            client = Client.objects.get(client_id=client_id)
            return client.default_redirect_uri
        except Client.DoesNotExist:
            return None

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        try:
            client = Client.objects.get(client_id=client_id)
            return client.default_scopes
        except Client.DoesNotExist:
            return None

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        pass

    def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
        pass

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        pass

    def rotate_refresh_token(self, request):
        pass

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass

    def save_token(self, token, request, *args, **kwargs):
        pass

    def save_bearer_token(self, token, request, *args, **kwargs):
        pass

    def validate_bearer_token(self, token, scopes, request):
        pass

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        pass

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        pass

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        pass

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        pass

    def validate_user(self, username, password, client, request, *args, **kwargs):
        pass

    def is_pkce_required(self, client_id, request):
        return Client.objects.filter(client_id=client_id).first().is_pkce_required

    def get_code_challenge(self, code, request):
        pass

    def get_code_challenge_method(self, code, request):
        pass

    def is_origin_allowed(self, client_id, origin, request, *args, **kwargs):
        pass
