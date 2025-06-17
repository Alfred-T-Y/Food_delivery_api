
from rest_framework import serializers
from authentication.models import User
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import check_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_bytes, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.urls import reverse


class RegisterSerializer(serializers.ModelSerializer):
    email=serializers.EmailField()
    username=serializers.CharField()
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        username = attrs.get('username', '')
        email = attrs.get('email', '')

        if not username.isalnum():
            raise serializers.ValidationError(
                'The Name should only contain alphanumeric characters'
            )
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'This Email is already used'
            )
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                'this Name is already used'
            )
        return attrs

    
    def create(self, validated_data):
        request=self.context.get('request')
        user = User.objects.create_user(**validated_data)
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
        email_body = 'Use this link below to verify your Email \n\n'+absurl
        data = {'email_body': email_body, 'to_email':user.email,
                'email_subject': 'Verify your Email'}

        Util.send_email(data)
        return user
    

class EmailVerificationSerializer(serializers.Serializer):
    
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
                'Email doesn\'t exist'
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
        models = User
        fields = ['email']

    def validate(self, attrs):
        email=attrs.get('email', '')
        request=self.context.get('request')
        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed(
                'This Email doesn\'t exist'
            )
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(request).domain
        relativeLink = reverse('password-reset-confirm', kwargs={'uidb64':uidb64, 'token':token})
        absurl = 'http://'+current_site+relativeLink
        email_body = 'Use this link to reset your Password \n\n'+absurl
        data = {'email_body': email_body, 'to_email':user.email,
                'email_subject': 'Reset your password'}

        Util.send_email(data)
        
        return attrs
    
class SetNewPasswordSerializer(serializers.Serializer):

    token=serializers.CharField()
    password=serializers.CharField(min_length=6,
        max_length=68, write_only=True)
    uidb64=serializers.CharField(write_only=True)
    
    class Meta:
        fields=['password','token','uidb64']

    def validate(self, attrs):

        try:
            password=attrs.get('password')
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')

            id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed(
                    'The reset Link is invalid', 401
                )
            user.set_password(password)
            user.save()
            
        except Exception as e:
            raise AuthenticationFailed(
                'The reset Link is invalid', 401
            )
        return super().validate(attrs)