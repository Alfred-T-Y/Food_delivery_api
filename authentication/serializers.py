
from rest_framework import serializers
from authentication.models import User
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import check_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

class RegisterSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError(
                'The Name should only contain alphanumeric characters'
            )
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class EmailVerificationSerializer(serializers.ModelSerializer):
    
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    username = serializers.CharField(read_only=True)
    tokens = serializers.CharField(read_only=True)

    class Meta():
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        #print('\n\n'+str(email)+str(password)+'\n\n')

        #user=auth.authenticate(email=email, password=password)
        user = User.objects.filter(email=email).first()


        if user is None:
            raise AuthenticationFailed(
                'Email incorrect'
            )
        if not check_password(password, user.password):
            raise AuthenticationFailed(
                'Password incorrect'
                )
        if not user.is_active:
            raise AuthenticationFailed(
                'Account disabled, contact admin'
            )
        if not user.is_verified:
            raise AuthenticationFailed(
                'Email is not verified'
            )
        return{
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

class RequestPasswordResetEmailSerializer(serializers.Serializer):

    email=serializers.EmailField()

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email=attrs['data'].get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(user.id)
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(attrs['request']).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://'+current_site+relativeLink
            email_body = 'Use this link to reset your Password \n\n'+absurl
            data = {'email_body': email_body, 'to_email':user.email,
                    'email_subject': 'Reset your password'}

            Util.send_email(data)
        
        return super().validate(attrs)
 