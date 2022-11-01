import base64
import datetime
import hashlib
import random
import string
from secrets import token_urlsafe
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth import authenticate
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views import View
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from django_oauth2.settings import REFRESH_TOKEN_EXPIRE_HOURS
from server_part.controller import CustomRequestValidator
from server_part.endpoints import server
from server_part.forms import AuthenticationPageForm
from server_part.jwt_controll import JWTManager
from server_part.models import AuthorizationCode, Client, Token
from server_part.serializers import KeysSerializer


class UnauthorizeClient(APIView):
    def get(self, request, *args, **kwargs):
        redirect_uri = request.query_params["post_logout_redirect_uri"]
        client_id = request.query_params['client_id']
        refresh_token = request.query_params['refresh_token']

        client = Client.objects.filter(client_id=client_id).prefetch_related("token_set").first()
        Token.objects.filter(refresh_token=refresh_token, client=client).first().delete()
        return redirect(redirect_uri)


class AuthorizeClient(View):
    renderer_classes = TemplateHTMLRenderer
    template_name = 'server_part/login.html'

    def __init__(self, *args, **kwargs):
        self._authorization_endpoint = server
        self.request_validator = CustomRequestValidator()
        super(AuthorizeClient, self).__init__(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        # # check

        client_id = request.GET.get("client_id")
        response_type = request.GET.get('response_type')
        redirect_uri = request.GET.get('redirect_uri')
        scopes = request.GET.get('scope')
        code_challenge = request.GET.get('code_challenge')
        code_challenge_method = request.GET.get('code_challenge_method')
        nonce = request.GET.get('nonce')
        state = request.GET.get('state')

        client = self.request_validator.validate_client_id(client_id, request)
        self.request_validator.validate_redirect_uri(client_id, redirect_uri, request)
        self.request_validator.validate_response_type(client_id, response_type, client, request)
        self.request_validator.validate_scopes(client_id, scopes, client, request)

        self._authorization_endpoint.client_id = client.client_id

        code = AuthorizationCode(client=client, scopes=scopes, redirect_uri=redirect_uri)
        code.nonce = nonce
        code.state = state
        code.expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

        if self.request_validator.is_pkce_required(client_id, request):
            code.challenge = code_challenge
            code.challenge_method = code_challenge_method

        code.save()

        return render(request, self.template_name, {'form': AuthenticationPageForm})

    # @csrf_exempt
    def post(self, request):
        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        if user:
            client_id = request.GET["client_id"]
            nonce = request.GET["nonce"]

            # todo check_scope()

            # redirect to redirect url + create authorization code
            client = Client.objects.filter(client_id=client_id).first()

            if user not in client.users.all():
                return

            code = AuthorizationCode.objects.filter(nonce=nonce).first()
            code.user = user

            if not client or not code:
                return

            if code.client != client:
                return

            code.code = "".join(random.sample(string.ascii_letters, 45))

            code.save()

            parameters = urlencode({
                "state": code.state,
                # "client_info": "wdcwdc",
                "code": code.code
            })

            return redirect(f'{client.redirect_uri}?{parameters}')

        else:
            messages.error(request, "Cannot find user with this email and password")
            return Response(template_name='server_part/login.html', data={
                "form": AuthenticationPageForm
            })


class TokenView(APIView):

    def __init__(self, *args, **kwargs):
        # Using the server from previous section
        self._token_endpoint = server
        self.request_validator = self._token_endpoint.request_validator
        super(TokenView, self).__init__(*args, **kwargs)

    def post(self, request):
        client_id, client_secret = base64.urlsafe_b64decode(
            request.META["HTTP_AUTHORIZATION"].split(" ")[1]) \
            .decode().split(":")

        str_code = request.data["code"]

        scopes = request.data["scope"]

        code = AuthorizationCode.objects.filter(code=str_code).first()

        # self.request_validator
        if datetime.datetime.utcnow().timestamp() > code.expires_at.timestamp():
            return

        if not code.client.client_id == client_id or not code.client.client_secret == client_secret:
            return

        # If you wish to include request specific extra credentials for
        # use in the validator, do so here.
        # credentials = {'foo': 'bar'}

        verifier = request.data["code_verifier"]

        varifier_after = (
            # https://tools.ietf.org/html/rfc7636#section-4.2
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")).decode()

        if code.challenge != varifier_after:
            return

        client = code.client

        self.token_manager = JWTManager()
        keys = self.token_manager.keys

        refresh_token = token_urlsafe(91)

        time_now = datetime.datetime.utcnow()
        refresh_exp = time_now + datetime.timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS)
        username = code.user.username

        decoded_token = self.token_manager.create_decoded(client_id=client_id, time_now=time_now, code=code,
                                                          username=username)

        access_token = self.token_manager.encode_token(payload=decoded_token, headers={
            "kid": keys.kid
        })

        token = Token(
            user=code.user,
            client=client,
            refresh_token=refresh_token,
            access_token=access_token,
            scopes=scopes,
            expires_at=refresh_exp
        )

        token.save()

        keys.token = token
        keys.save()

        code.delete()

        response = {
            'id_token': access_token,
            'token_type': 'Bearer',
            'not_before': time_now.timestamp(),
            'scope': scopes,
            'refresh_token': refresh_token,
            'refresh_token_expires_in': refresh_exp.timestamp() - time_now.timestamp()}

        # All requests to /token will return a json response, no redirection.
        # return response_from_return(headers, body, status)

        return Response(response)


class TokenRefresh(APIView):

    def post(self, request):
        refresh_token = request.data.get("refresh_token", "")
        token = Token.objects.filter(refresh_token=refresh_token,
                                     expires_at__gte=datetime.datetime.utcnow()).prefetch_related("keys_set").first()
        if not token:
            return Response(data={"message": "Wrong refresh token or expired"}, status=404)
        key = token.keys_set.first()
        if not key:
            return Response(data={"message": "Error with key"}, status=500)
        self.token_manager = JWTManager(algorithm=key.algorithm, private_key=key.private_key, public_key=key.public_key)

        time_now = datetime.datetime.utcnow()

        client_id = token.client_id
        username = token.user.username

        decoded_token = self.token_manager.create_decoded(client_id=client_id,
                                                          time_now=time_now,
                                                          username=username)

        access_token = self.token_manager.encode_token(payload=decoded_token, headers={
            "kid": key.kid
        })

        token.access_token = access_token
        token.save()
        return Response(data={"token": access_token})


class CheckTokenPermissions(APIView):

    def get(self, request):
        try:
            token = request.META["HTTP_AUTHORIZATION"].split()[1]
        except Exception:
            return {"errors": "Error with token authorization"}

        user = Token.objects.filter(access_token=token).first().user
        return Response(data={"result": [group.name for group in user.groups.all()]})


class ReturnAllJWK(APIView):

    def get(self, request):
        if not request.GET.get("client_id"):
            return Response(data={"message": "Please specify client_id param"})

        client = Client.objects.filter(client_id=request.GET["client_id"]).prefetch_related(
            "token_set__keys_set").first()
        client_tokens = client.token_set.all().prefetch_related("keys_set")
        res = []
        for obj in client_tokens:
            if obj.keys_set.first():
                res.append(obj.keys_set.first())

        serializer = KeysSerializer(res, many=True)

        return Response(data={"keys": serializer.data})


def response_from_return(headers, body, status):
    response = HttpResponse(content=body, status=status)
    for k, v in headers.items():
        response[k] = v
    return response


def response_from_error(e):
    return HttpResponseBadRequest('Evil client is unable to send a proper request. Error is: ' + e.description)
