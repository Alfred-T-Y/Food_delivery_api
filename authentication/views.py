from django.shortcuts import render
from rest_framework import generics, status, views
from authentication.serializers import (RegisterSerializer, 
    EmailVerificationSerializer, LoginSerializer, 
    RequestPasswordResetEmailSerializer, SetNewPasswordSerializer,
    PasswordTokenCheckAPISerializer, LogoutSerializer)
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRender
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import permissions

class RegisterView(generics.GenericAPIView):

    serializer_class=RegisterSerializer
    renderer_classes=(UserRender,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data,
            context={'request':request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data

        
        return Response(user_data, status=status.HTTP_201_CREATED)
    


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):

        serializer = self.serializer_class(data=request.data,
            context={'request':request})
        serializer.is_valid(raise_exception=True)
        
        return Response({'email': 'Sucessfully actived'}, status=status.HTTP_200_OK)
        



class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    
    serializer_class = RequestPasswordResetEmailSerializer

    def post(self, request):
        serializer=self.serializer_class(data=request.data, 
            context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'success': 'We have sent you a link to reset your password.'
            'Check your Mails.'},status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView): 

    serializer_class = PasswordTokenCheckAPISerializer

    def get(self, request, uidb64, token):

        serializer=self.serializer_class(data=request.data,
            context={'uidb64':uidb64, 'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'succes':True, 'massage':'Credentials valid', 'uidb64':uidb64, 'token':token},
            status=status.HTTP_200_OK)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class=SetNewPasswordSerializer

    def patch(self, request):

        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True,'message':'Password reset success'},
            status=status.HTTP_200_OK)
    
class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):

        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

