from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    # _id = ObjectIdField(primary_key=True)
    # first_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('visitor', 'Visitor'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='visitor')

class Meta:
        db_table = 'auth_user'