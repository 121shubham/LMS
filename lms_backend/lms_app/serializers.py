from rest_framework import serializers
from .models import CustomUser

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 
            'role', 'is_approved', 'is_staff', 'is_active',
            'date_joined', 'last_login'
        ]
        read_only_fields = ['date_joined', 'last_login']