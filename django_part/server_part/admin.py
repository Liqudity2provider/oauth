from django.contrib import admin

# Register your models here.
from server_part.models import Client, AuthorizationCode, Token, Keys

admin.site.register(Client)
admin.site.register(AuthorizationCode)
admin.site.register(Token)
admin.site.register(Keys)
