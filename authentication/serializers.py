
from rest_framework import serializers
from authentication.models import Client


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    
    class Meta:
        model = Client
        fields = ['email', 'clientname', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        clientname = attrs.get('clientname', '')

        if not clientname.isalnum():
            raise serializers.ValidationError(
                'The clientname should only contain alphanumeric characters'
            )
        return attrs
    
    def create(self, validated_data):
        return Client.objects.create_client(**validated_data)