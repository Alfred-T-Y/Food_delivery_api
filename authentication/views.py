from django.shortcuts import render
from rest_framework import generics, status, views
from authentication.serializers import (RegisterSerializer, 
    EmailVerificationSerializer, LoginSerializer, 
    RequestPasswordResetEmailSerializer, SetNewPasswordSerializer)
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

class RegisterView(generics.GenericAPIView):

    serializer_class=RegisterSerializer
    renderer_classes=(UserRender,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data,
            context={'request':request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data

        
        return Response(user_data, status=status.HTTP_200_OK)
    


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        
        token = request.GET.get('token')

        try:

            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()

            return Response({'email': 'Sucessfully actived'}, status=status.HTTP_200_OK)


        except jwt.ExpiredSignatureError as identifier:
            
            return Response({'error':'activation expired'}, status=status.HTTP_400_BAD_REQUEST)
        
        except jwt.exceptions.DecodeError as identifier:
            
            return Response({'error':'invalid token'}, status=status.HTTP_400_BAD_REQUEST)

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

    def get(self, request, uidb64, token):

        try:
            id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':'This link isn\'t valid anymore,please request a new one'},
                    status=status.HTTP_401_UNAUTHORIZED)
            
            return Response({'succes':True, 'massage':'Credentials valid', 'uidb64':uidb64, 'token':token},
                    status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'error':'This link isn\'t valid,please request a new one'},
                    status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class=SetNewPasswordSerializer

    def patch(self, request):

        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True,'message':'Password reset success'},
            status=status.HTTP_200_OK)