#lms_backend/lms_backend/urls.py

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static


from rest_framework_simplejwt.views import TokenRefreshView
from lms_app.views import CustomTokenObtainPairView

# Legacy session-based endpoints (we’ll keep them around but prefer JWT)
from lms_app.views import api_signup, api_login

urlpatterns = [
    path('admin/', admin.site.urls),

    # Legacy session-based endpoints (optional; can be removed once JWT is fully adopted)
    path('api/signup/', api_signup, name='api_signup'),
    path('api/login/', api_login, name='api_login'),

    # New JWT endpoints
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    

    # All other API routes:
    path('api/', include('lms_app.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
