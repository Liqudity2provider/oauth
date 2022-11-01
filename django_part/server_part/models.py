from django.contrib.auth.models import User

from django.db import models

from django_oauth2.settings import DJANGO_PATH


class Group(models.Model):
    name = models.CharField(max_length=100)
    users = models.ManyToManyField(User)

    def __str__(self):
        return self.name


class Client(models.Model):
    users = models.ManyToManyField(User)

    client_id = models.CharField(max_length=120, unique=True)
    client_secret = models.CharField(max_length=120, unique=True)
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # user = db.relationship("User", backref=backref("user", uselist=False))
    authorization_endpoint = models.CharField(max_length=400, null=True,
                                              default=DJANGO_PATH + "authorize_client/")  # will be created automatically
    grant_type = models.CharField(max_length=120, null=True,
                                  default="authorization_code")  # choices=[('authorization_code', 'Authorization code')])
    response_type = models.CharField(max_length=4, default="code")  # choices=[('code', 'Authorization code')])
    # You could represent it either as a list of keys or by serializing
    # the scopes into a string.
    scopes = models.CharField(max_length=120)

    # You might also want to mark a certain set of scopes as default
    # scopes in case the client does not specify any in the authorization
    default_scopes = models.CharField(max_length=120)
    # You could represent the URIs either as a list of keys or by
    # serializing them into a string.
    redirect_uri = models.CharField(max_length=400)  # todo set when create

    # default_redirect_uri = models.CharField(max_length=400, )  # todo set when create

    is_pkce_required = models.BooleanField(default=True)

    def __str__(self):
        return self.client_id


class AuthorizationCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    scopes = models.TextField()
    redirect_uri = models.TextField()
    code = models.CharField(max_length=100, unique=True, null=True)
    expires_at = models.DateTimeField()
    challenge = models.CharField(max_length=128, null=True)
    challenge_method = models.CharField(max_length=6, null=True)
    nonce = models.CharField(max_length=128, null=True)
    state = models.CharField(max_length=128, null=True)

    def __str__(self):
        return f"Code: Client - {self.client}, exp at - {self.expires_at.isoformat()}"

    def __repr__(self):
        return f"Code: Client - {self.client}, exp at - {self.expires_at.isoformat()}"


class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    scopes = models.TextField()
    access_token = models.CharField(max_length=100, unique=True)
    refresh_token = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()


class Keys(models.Model):
    token = models.ForeignKey(Token, on_delete=models.CASCADE, null=True)
    public_key = models.CharField(max_length=500)
    private_key = models.CharField(max_length=2000)
    algorithm = models.CharField(max_length=50)
    kid = models.CharField(max_length=30)

