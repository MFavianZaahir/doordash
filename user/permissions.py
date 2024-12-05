from rest_framework.permissions import BasePermission

class IsManager(BasePermission):
    """
    Custom permission to grant access only to users with the 'manager' role.
    """

    def has_permission(self, request, view):
        # Ensure the user is authenticated and has the 'manager' role
        return request.user and request.user.is_authenticated and request.user.role == 'manager'
