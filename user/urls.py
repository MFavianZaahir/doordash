from django.urls import path
from user.views import UserListCreateView, LoginView, UpdateUserView, VerifyOTPView, UserDetailView
# from django_conf import settings
from django.conf.urls.static import static, settings

urlpatterns = [
    # User List/Create endpoint
    # path('user/', UserDetailView.as_view(), name='user-list-create'),
    path('user/', UserListCreateView.as_view(), name='user-list-create'),
    # User Detail (Retrieve, Update, Delete) endpoint
    path('user/<int:pk>/', UserDetailView.as_view(), name='user-detail'),
    path('users/<int:pk>/', UpdateUserView.as_view(), name='update-user'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)