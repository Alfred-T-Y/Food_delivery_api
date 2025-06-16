from django.urls import path
from .views import (RegisterView, VerifyEmail, LoginAPIView,
    PasswordTokenCheckAPI)
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset/<uidb64>/token/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm')
]
