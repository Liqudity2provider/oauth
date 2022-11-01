from django.urls import path

from server_part.views import AuthorizeClient, TokenView, UnauthorizeClient, CheckTokenPermissions, ReturnAllJWK, \
    TokenRefresh

urlpatterns = [
    path('authorize_client/', AuthorizeClient.as_view(), name='authorize_client'),
    path('token/', TokenView.as_view(), name="token_view"),
    path('unauthorize_client/', UnauthorizeClient.as_view(), name="unauthorize_client"),
    path('check_token_permissions', CheckTokenPermissions.as_view(), name="check_token_permissions"),
    path('discovery/keys', ReturnAllJWK.as_view(), name="discovery_keys"),
    path('refresh_token/', TokenRefresh.as_view(), name="refresh_token"),
]
