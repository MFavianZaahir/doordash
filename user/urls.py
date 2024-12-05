from django.urls import path
from user.views import UserListCreateView, UserDetailView, LoginView, UpdateUserView

urlpatterns = [
    # User List/Create endpoint
    path('user/', UserListCreateView.as_view(), name='user-list-create'),
    # User Detail (Retrieve, Update, Delete) endpoint
    path('user/<int:pk>/', UserDetailView.as_view(), name='user-detail'),
    path('login/', LoginView.as_view(), name='user-login'),
    path('users/<int:pk>/', UpdateUserView.as_view(), name='update-user'),
]