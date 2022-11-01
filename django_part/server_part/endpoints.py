from server_part.controller import CustomRequestValidator

from oauthlib.oauth2 import WebApplicationServer

validator = CustomRequestValidator()
server = WebApplicationServer(validator)
