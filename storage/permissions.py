from rest_framework import permissions
from .models import UserPermission

class IsSuperuserOrOwner(permissions.BasePermission):
    """
    Permission to only allow superusers or owners to view/edit objects.
    """
    def has_object_permission(self, request, view, obj):
        # Superusers have all permissions
        if request.user.is_superuser:
            return True
        
        # Owners have permissions on their own objects
        if hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        
        return False

class HasFolderPermission(permissions.BasePermission):
    """
    Permission to check if user has specific folder permissions.
    """
    def has_permission(self, request, view):
        # Superusers have all permissions
        if request.user.is_superuser:
            return True
        
        # Check for specific folder permissions
        folder_id = view.kwargs.get('folder_id') or request.data.get('folder')
        if folder_id:
            return self.check_folder_permission(request.user, folder_id, request.method)
        
        return True
    
    def has_object_permission(self, request, view, obj):
        # Superusers have all permissions
        if request.user.is_superuser:
            return True
        
        # Check permissions based on the object type
        if hasattr(obj, 'folder'):
            folder = obj.folder
        elif hasattr(obj, 'id') and obj.__class__.__name__ == 'Folder':
            folder = obj
        else:
            return False
        
        return self.check_folder_permission(request.user, folder.id, request.method)
    
    def check_folder_permission(self, user, folder_id, method):
        """Check if user has permission for specific action on folder"""
        permission_map = {
            'GET': 'read',
            'POST': 'create',
            'PUT': 'update',
            'PATCH': 'update',
            'DELETE': 'delete',
        }
        
        required_permission = permission_map.get(method, 'read')
        
        return UserPermission.objects.filter(
            user=user,
            folder_id=folder_id,
            permission=required_permission
        ).exists()

class CanDownloadImage(permissions.BasePermission):
    """
    Permission to check if user can download images.
    """
    def has_object_permission(self, request, view, obj):
        # Superusers can download everything
        if request.user.is_superuser:
            return True
        
        # Check download permission for the folder
        return UserPermission.objects.filter(
            user=request.user,
            folder=obj.folder,
            permission='download'
        ).exists()