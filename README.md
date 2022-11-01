# oauth

## Project consists of two parts: Django and Flask
### Django part takes responsibilities as Azure Active Directory (creates client, creates tokens for client, validates tokens)
### Flask part takes responsibility of validating tokens from user side, and as web-client app.


## Configure applications
1. Clone repository
2. Create cert.pem and key.pem for Django https https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl
3. Create 2 virtual environments for Flask and Django apps. Because requirements are different, so venvs also should be different. https://docs.python.org/3/library/venv.html
4. Install requirements for both of venvs (django_part/requirements.txt and flask_part/requirements.txt)
5. Create app_config.py file in flask_part directory to specify the configuration for Flask part.
6. Copy configuration from app_config_ex.py and delete this file
7. Then specify all params in file. 
8. Run both Django and Flask servers on different ports.