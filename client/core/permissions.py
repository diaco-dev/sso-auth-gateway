from rest_framework.permissions import BasePermission


class IsOAuthAuthenticated(BasePermission):
    """Permission that requires OAuth authentication"""

    def has_permission(self, request, view):
        return (
                request.user and
                request.user.is_authenticated and
                hasattr(request.user, 'oauth_sub')
        )


class IsAdminOrManager(BasePermission):
    """Permission for admin or manager roles only"""

    def has_permission(self, request, view):
        return (
                request.user and
                request.user.is_authenticated and
                request.user.role in ['admin', 'manager']
        )


class IsTaskOwnerOrAssigned(BasePermission):
    """Permission for task owner or assigned user"""

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        # Admin and managers can access any task
        if request.user.role in ['admin', 'manager']:
            return True

        # Task creator or assignee can access
        return (
                obj.created_by == request.user or
                obj.assigned_to == request.user
        )


class CanEditTask(BasePermission):
    """Permission to edit tasks"""

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        # Admin can edit anything
        if request.user.role == 'admin':
            return True

        # Manager can edit tasks in their scope
        if request.user.role == 'manager':
            return True

        # Users can edit their own created tasks
        if request.user.role == 'user':
            return obj.created_by == request.user

        # Viewers cannot edit
        return False


class CanDeleteTask(BasePermission):
    """Permission to delete tasks"""

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        # Only admin and task creator can delete
        return (
                request.user.role == 'admin' or
                obj.created_by == request.user
        )