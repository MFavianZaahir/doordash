from django.urls import path, include
from rest_framework.routers import DefaultRouter
from django.contrib import admin
# from user.views import UserViewSet

# Create a router and register the UserViewSet
# router = DefaultRouter()
# router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('api/', include('user.urls')),
    path('admin/', admin.site.urls),
]
