
from rest_framework import serializers
from authentication.models import User
#from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import check_password


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
        user = User.objects.get(email=email)


        if not user:
            raise AuthenticationFailed(
                'Email or Password incorrect'
            )
        if not check_password(password, user.password):
            raise AuthenticationFailed(
                'Email or Password incorrect'
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

