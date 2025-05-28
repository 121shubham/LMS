from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, permissions, filters
from rest_framework.response import Response
import json
from .models import CustomUser
from lms_app.serializers import UserSerializer

User = get_user_model()

@csrf_exempt
def api_signup(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body)
        name = data.get('name')
        username = data.get('username')
        mobile = data.get('mobile')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    if not all([mobile,email, password, role]):
        return JsonResponse({'error': 'All fields are required'}, status=400)

    try:
        user = CustomUser.objects.create_user(
            username=username,
            mobile=mobile,
            email=email,
            password=password,
            role=role
        )

        if role.lower() == 'admin':
            user.is_staff = True
            user.is_superuser = True
        else:
            user.is_staff = True

        user.save()
        return JsonResponse({'message': 'User created successfully'}, status=201)

    except IntegrityError as e:
        if 'username' in str(e):
            return JsonResponse({'error': 'Username already exists.'}, status=400)
        elif 'email' in str(e):
            return JsonResponse({'error': 'Email already exists.'}, status=400)
        else:
            return JsonResponse({'error': 'Could not create account.'}, status=400)

@csrf_exempt
def api_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    if not all([username, password]):
        return JsonResponse({'error': 'Username and password required'}, status=400)

    try:
        user = CustomUser.objects.get(username__iexact=username,role__iexact=role)
        if user.check_password(password):
            login(request, user)
            return JsonResponse({
                'message': 'Login successful',
                'role': user.role,
                'username': user.username,
                'is_approved': user.is_approved,
                'is_staff': user.is_staff,
            }, status=200)
        else:
            return JsonResponse({'error': 'Invalid password'}, status=401)
    except CustomUser.DoesNotExist:
        return JsonResponse({'error': 'Invalid username or password'}, status=401)

class UserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['role', 'is_approved', 'is_staff', 'is_active']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering_fields = ['date_joined', 'last_login']
