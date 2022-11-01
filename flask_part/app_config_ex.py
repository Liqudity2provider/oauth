# You can leave this as it is
URL_PATH_APP = "http://127.0.0.1:5000"  # url path for Flask app
BASIC_SERVER_URL = "https://127.0.0.1:8000/"  # url part for Django server (only if use all custom creation of tokens flow)
REDIRECT_PATH = "/getToken"  # redirect for POST request from Django when using custom flow
ENDPOINT = f"{BASIC_SERVER_URL}authorize_client/"
FULL_REDIRECT_PATH = URL_PATH_APP + REDIRECT_PATH
TOKEN_ENDPOINT = f"{BASIC_SERVER_URL}token/"
LOGOUT_ENDPOINT = f"{BASIC_SERVER_URL}unauthorize_client/"
CHECK_PERMISSIONS = f"{BASIC_SERVER_URL}check_token_permissions"

# Next params you need to specify
SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'  # specify db uri

CLIENT_ID = "123456789"  # Application (client) ID of app registration (only if use all custom creation of tokens flow)
CLIENT_SECRET = "123456789876543212345678987654321"  # (only if use all custom creation of tokens flow)

FLASK_SECRET = '12345678987654321234567898765432123456789'  # create any secret string for flask app

# ------- Azure -------
clientId = ""
tenant_id = ""
audience = ''
token_validation_endpoint = f"https://login.microsoftonline.com/{tenant_id}/discovery/keys?appid={clientId}"

# ------- custom -------
# clientId = ""
# token_validation_endpoint = f"https://127.0.0.1:8000/discovery/keys?client_id={clientId}"
