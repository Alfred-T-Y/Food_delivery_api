from django.db import models

# Create your models here.
from django.contrib.auth.models import (
    AbstractBaseUser,BaseUserManager,PermissionsMixin)


class ClientManager(BaseUserManager):
    def create_client(self, email, clientname, password=None):
        if email is None:
            raise TypeError('Client must have an email')
        if clientname is None:
            raise TypeError('Client must have a clientname')

        client = self.model(
            email=self.normalize_email(email),
            clientname=clientname
        )
        client.set_password(password)
        client.save()
        return client

    def create_superuser(self, email, clientname, password=None):
        if password is None:
            raise TypeError('Superuser must have a password')

        admin = self.create_client(email, clientname, password)
        admin.is_superuser = True
        admin.is_staff = True
        admin.save()
        return admin

class Client(AbstractBaseUser, PermissionsMixin):
    clientname = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    create_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['clientname']  

    objects = ClientManager()

    def __str__(self):
        return self.email

    def tokens(self):
        return ''
    
    
    