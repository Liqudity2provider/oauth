from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import declarative_base, backref

from wsgi import app

Base = declarative_base()

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    _password = db.Column(db.String(128))
    # groups = relationship("Group", secondary=association_table, backref='users')
    groups = db.Column(db.String(120), unique=True, nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username


class PCKE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_verifier = db.Column(db.String(500), unique=True, nullable=False)
    transformation = db.Column(db.String(10), unique=True, nullable=True)
    code_challenge = db.Column(db.String(500))
    client = db.relationship("Client", backref=backref("client", uselist=False))


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(120), unique=True)
    client_secret = db.Column(db.String(120), unique=True)
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # user = db.relationship("User", backref=backref("user", uselist=False))
    authorization_endpoint = db.Column(db.String(400))  # will be created automatically
    grant_type = db.Column(db.String(18))  # choices=[('authorization_code', 'Authorization code')])
    response_type = db.Column(db.String(4))  # choices=[('code', 'Authorization code')])
    # You could represent it either as a list of keys or by serializing
    # the scopes into a string.
    scopes = db.Column(db.String(400))

    # You might also want to mark a certain set of scopes as default
    # scopes in case the client does not specify any in the authorization
    default_scopes = db.Column(db.String(400), nullable=True)
    # You could represent the URIs either as a list of keys or by
    # serializing them into a string.
    redirect_uris = db.Column(db.String(400))  # todo set when create

    # You might also want to mark a certain URI as default in case the
    # client does not specify any in the authorization
    default_redirect_uri = db.Column(db.String(400), nullable=True)
