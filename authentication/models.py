from django.db import models

# Create your models here.
from django.contrib.auth.models import (
    AbstractBaseUser,BaseUserManager,PermissionsMixin)
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):

    def create_user(self, email, username, password=None):
        
        if email is None:
            raise TypeError('The Email is required')
        if username is None:
            raise TypeError('The Name is required')

        user = self.model(
            email=self.normalize_email(email),
            username=username
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, username, password=None):

        if password is None:
            raise TypeError('The Password is required')

        user = self.create_user(email, username, password)
        user.is_superuser = True
        user.is_active = True
        user.is_staff = True
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    create_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']  

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        tokens = RefreshToken.for_user(self)
        return {
            'refresh':str(tokens),
            'access':str(tokens.access_token)
        }
    
    
    