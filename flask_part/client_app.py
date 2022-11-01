import base64
import json
import os
import random
import string
from urllib.parse import urlencode

import jwt
import requests
from flask import Flask, render_template, session, redirect, url_for, request
from jwt import PyJWKClient, InvalidAudienceError, ExpiredSignatureError, PyJWKSetError

from app_config import ENDPOINT, CLIENT_ID, FULL_REDIRECT_PATH, CLIENT_SECRET, TOKEN_ENDPOINT, LOGOUT_ENDPOINT, \
    REDIRECT_PATH, token_validation_endpoint, CHECK_PERMISSIONS, FLASK_SECRET
from flask_session import Session  # https://pythonhosted.org/Flask-Session
from models import Client, db, PCKE
from utils import generate_state, quote_plus, _generate_pkce_code_verifier, _nonce_hash, decode_id_token

template_dir = os.path.abspath('templates')
app = Flask(__name__, template_folder=template_dir)
app.secret_key = FLASK_SECRET
app.config['SESSION_TYPE'] = 'filesystem'

Session(app)

from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


# @app.route("/create_client")
# def create_client():
#     new_client = Client(
#         id=1,
#         client_id="",
#         client_secret="",
#         authorization_endpoint="",
#         grant_type="authorization_code",
#         response_type='code',
#         scopes="",
#         redirect_uris="",
#     )
#     db.session.add_all([new_client])
#     db.session.commit()
#
#     return "create client " + new_client.client_id
#
#
# @app.route("/create_pcke")
# def create_pcke():
#     client = Client.query.get(1)
#     new_pcke = PCKE(
#         id=1,
#         code_verifier="",
#         transformation="",
#         code_challenge="",
#         client=client
#     )
#     db.session.add_all([new_pcke])
#     db.session.commit()
#
#     return "created pcke " + new_pcke.code_verifier


@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('index.html', user=session["user"])


def build_auth_flow():
    authorization_endpoint = ENDPOINT  # url of the oauth2 server

    nonce = "".join(random.sample(string.ascii_letters, 16))
    hashed_nonce = _nonce_hash(nonce)

    pkce = _generate_pkce_code_verifier()

    state = generate_state()

    params = {'client_id': CLIENT_ID,
              'response_type': 'code',
              'redirect_uri': FULL_REDIRECT_PATH,
              'scope': 'openid getGroupAccess',
              'state': state,
              'code_challenge': pkce["code_challenge"],
              'code_challenge_method': pkce["transformation"],
              'nonce': hashed_nonce,
              }
    sep = "?"
    url_for_login = "%s%s%s" % (authorization_endpoint, sep, urlencode(params))

    flow = {
        # 'state': 'IavpwbTchmeXnRGo',
        'redirect_uri': FULL_REDIRECT_PATH,
        'scope': ['getGroupAccess', 'openid'],
        'auth_uri': url_for_login,
        'state': state,
        'code_verifier': pkce["code_verifier"],
        'nonce': hashed_nonce,
        'claims_challenge': None}
    return flow


@app.route("/login")
def login():
    session["flow"] = build_auth_flow()
    return render_template("login.html", auth_url=session["flow"]["auth_uri"])


class CustomClient:
    def __init__(self, client_id, client_secret, token_endpoint, http_client=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.default_headers = {}
        self.token_endpoint = token_endpoint

        if not http_client:
            import requests  # Lazy loading
            self._http_client = requests.Session()
        else:
            self._http_client = http_client

    def create_post_request_to_token(self,
                                     params=None,  # a dict to be sent as query string to the endpoint
                                     data=None,  # All relevant data, which will go into the http body
                                     headers=None,  # a dict to be sent as request headers
                                     **kwargs  # Relay all extra parameters to underlying requests
                                     ):
        _data = {
            'client_id': self.client_id,
            # 'client_secret': self.client_secret,
        }

        _data.update(data or {})  # So the content in data param prevails
        _data = {k: v for k, v in _data.items() if v}  # Clean up None values

        _headers = {'Accept': 'application/json'}
        _headers.update(self.default_headers)
        _headers.update(headers or {})

        _headers["Authorization"] = "Basic " + base64.b64encode("{}:{}".format(
            # Per https://tools.ietf.org/html/rfc6749#section-2.3.1
            # client_id and client_secret needs to be encoded by
            # "application/x-www-form-urlencoded"
            # https://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1
            # BEFORE they are fed into HTTP Basic Authentication
            quote_plus(self.client_id), quote_plus(self.client_secret)
        ).encode("ascii")).decode("ascii")

        return self._http_client.post(
            self.token_endpoint,
            headers=_headers,
            params=params,
            data=_data,
            **kwargs)


@app.route(REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    GRANT_TYPE = "authorization_code"

    try:
        state = request.args["state"]
        code = request.args["code"]

        if state != session["flow"]["state"]:
            return

        data = {
            "code": code,
            "scope": " ".join(session["flow"]['scope']),
            "redirect_uri": session["flow"]["redirect_uri"],
            'grant_type': GRANT_TYPE,
            "code_verifier": session["flow"]["code_verifier"]
        }

        client = CustomClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, token_endpoint=TOKEN_ENDPOINT)

        response = client.create_post_request_to_token(
            data=data
        )
        result = response.json()

        result["id_token_claims"] = decode_id_token(result["id_token"])

        nonce_in_id_token = result.get("id_token_claims", {}).get("nonce")
        expected_hash = _nonce_hash(session["flow"]["nonce"])
        if _nonce_hash(nonce_in_id_token) != expected_hash:
            raise RuntimeError(
                'The nonce in id token ("%s") should match our nonce ("%s")' %
                (nonce_in_id_token, expected_hash))
        session["user"] = result["id_token_claims"]
        session["refresh_token"] = result["refresh_token"]
        session["token"] = result["id_token"]
        print(result["id_token"])
        return redirect(url_for("index"))

    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        redirect("login")
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        LOGOUT_ENDPOINT +
        "?post_logout_redirect_uri=" + url_for("index", _external=True) +
        "&client_id=" + CLIENT_ID +
        "&refresh_token=" + refresh_token)


@app.route("/check_permissions", methods=['GET'])
def check_permissions():
    perms = requests.get(  # Use token to call downstream service
        CHECK_PERMISSIONS,
        headers={'Authorization': 'Bearer ' + session["token"]},
    ).json()
    return {"groups": perms}


@app.route("/validate_token", methods=['GET', 'POST'])
def validate_token():
    message = ""
    if request.method == "POST":
        token = request.form.get("token")

        url = token_validation_endpoint

        jwks_client = PyJWKClient(url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        to_decode = {
            "jwt": token,
            "key": signing_key.key,
            "algorithms": ["RS256"],
            "options": {"verify_exp": True},
        }

        if "microsoft" in token_validation_endpoint:
            from app_config import audience
            to_decode["audience"] = audience

        try:
            data = jwt.decode(
                **to_decode
            )

            message = f"Token validated. \n Data : {json.dumps(data)}"

        except ValueError as e:
            print({"Error": str(e.args)})
            message = "Error with token decoding or signing key"
            return render_template("validate_token.html", messages=message)
        except InvalidAudienceError as e:
            print({"Error": str(e.args)})
            message = e.args
            return render_template("validate_token.html", messages=message)
        except PyJWKSetError as e:
            message = "Error with token audience. Token can't be validated"
            return render_template("validate_token.html", messages=message)
        except ExpiredSignatureError as e:
            print({"Error": str(e.args)})
            message = "Token has expired signature"
            return render_template("validate_token.html", messages=message)

    return render_template("validate_token.html", messages=message)


# app.jinja_env.globals.update(_build_auth_code_flow=_build_auth_code_flow)  # Used in template

if __name__ == "__main__":
    app.run()
