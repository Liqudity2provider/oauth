import base64
import json
import time


def decode_part(raw, encoding="utf-8"):
    """Decode a part of the JWT.

    JWT is encoded by padding-less base64url,
    based on `JWS specs <https://tools.ietf.org/html/rfc7515#appendix-C>`_.

    :param encoding:
        If you are going to decode the first 2 parts of a JWT, i.e. the header
        or the payload, the default value "utf-8" would work fine.
        If you are going to decode the last part i.e. the signature part,
        it is a binary string so you should use `None` as encoding here.
    """
    raw += '=' * (-len(raw) % 4)  # https://stackoverflow.com/a/32517907/728675
    raw = str(
        # On Python 2.7, argument of urlsafe_b64decode must be str, not unicode.
        # This is not required on Python 3.
        raw)
    output = base64.urlsafe_b64decode(raw)
    if encoding:
        output = output.decode(encoding)
    return output


def decode_id_token(id_token, client_id=None, issuer=None, nonce=None, now=None):
    """Decodes and validates an id_token and returns its claims as a dictionary.

    ID token claims would at least contain: "iss", "sub", "aud", "exp", "iat",
    per `specs <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_
    and it may contain other optional content such as "preferred_username",
    `maybe more <https://openid.net/specs/openid-connect-core-1_0.html#Claims>`_
    """
    decoded = json.loads(decode_part(id_token.split('.')[1]))
    err = None  # https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
    _now = int(now or time.time())
    skew = 120  # 2 minutes
    TIME_SUGGESTION = "Make sure your computer's time and time zone are both correct."
    if _now + skew < decoded.get("nbf", _now - 1):  # nbf is optional per JWT specs
        # This is not an ID token validation, but a JWT validation
        # https://tools.ietf.org/html/rfc7519#section-4.1.5
        err = "0. The ID token is not yet valid. " + TIME_SUGGESTION
    if issuer and issuer != decoded["iss"]:
        # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
        err = ('2. The Issuer Identifier for the OpenID Provider, "%s", '
               "(which is typically obtained during Discovery), "
               "MUST exactly match the value of the iss (issuer) Claim.") % issuer
    if client_id:
        valid_aud = client_id in decoded["aud"] if isinstance(
            decoded["aud"], list) else client_id == decoded["aud"]
        if not valid_aud:
            err = (
                      "3. The aud (audience) claim must contain this client's client_id "
                      '"%s", case-sensitively. Was your client_id in wrong casing?'
                      # Some IdP accepts wrong casing request but issues right casing IDT
                  ) % client_id
    # Per specs:
    # 6. If the ID Token is received via direct communication between
    # the Client and the Token Endpoint (which it is during _obtain_token()),
    # the TLS server validation MAY be used to validate the issuer
    # in place of checking the token signature.
    if _now - skew > decoded["exp"]:
        err = "9. The ID token already expires. " + TIME_SUGGESTION
    if nonce and nonce != decoded.get("nonce"):
        err = ("11. Nonce must be the same value "
               "as the one that was sent in the Authentication Request.")
    if err:
        raise RuntimeError("%s Current epoch = %s.  The id_token was: %s" % (
            err, _now, json.dumps(decoded, indent=2)))
    return decoded
