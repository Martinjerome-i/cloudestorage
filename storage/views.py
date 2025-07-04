from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, Http404
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Folder, Image, UserPermission, AuditLog
from .serializers import FolderSerializer, ImageSerializer, UserPermissionSerializer, AuditLogSerializer, UserSerializer
from .permissions import IsSuperuserOrOwner, HasFolderPermission, CanDownloadImage
import json

# Authentication Views
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    """Dashboard view showing user's folders and recent activities"""
    if request.user.is_superuser:
        folders = Folder.objects.filter(is_deleted=False)
        images = Image.objects.filter(is_deleted=False)
    else:
        # Get folders user has permission to access
        permitted_folders = UserPermission.objects.filter(
            user=request.user
        ).values_list('folder_id', flat=True)
        
        folders = Folder.objects.filter(
            Q(id__in=permitted_folders) | Q(created_by=request.user),
            is_deleted=False
        ).distinct()
        
        images = Image.objects.filter(
            folder__in=folders,
            is_deleted=False
        )
    
    # Get recent audit logs
    recent_logs = AuditLog.objects.filter(user=request.user)[:10]
    
    context = {
        'folders_count': folders.count(),
        'images_count': images.count(),
        'recent_logs': recent_logs,
        'user': request.user,
    }
    
    return render(request, 'dashboard.html', context)

@login_required
def folders_view(request):
    """View for managing folders"""
    if request.user.is_superuser:
        folders = Folder.objects.filter(is_deleted=False)
    else:
        permitted_folders = UserPermission.objects.filter(
            user=request.user
        ).values_list('folder_id', flat=True)
        
        folders = Folder.objects.filter(
            Q(id__in=permitted_folders) | Q(created_by=request.user),
            is_deleted=False
        ).distinct()
        
    folders = folders.prefetch_related('images')
    
    # Get user permissions for each folder
    user_permissions = {}
    if not request.user.is_superuser:
        permissions = UserPermission.objects.filter(
            user=request.user,
            folder__in=folders
        ).values('folder_id', 'permission')
        
        for perm in permissions:
            folder_id = perm['folder_id']
            if folder_id not in user_permissions:
                user_permissions[folder_id] = []
            user_permissions[folder_id].append(perm['permission'])
    
    # Add permissions to folder objects
    for folder in folders:
        if request.user.is_superuser or folder.created_by == request.user:
            folder.user_permissions = ['view', 'create', 'update', 'delete', 'download']
        else:
            folder.user_permissions = user_permissions.get(folder.id, [])
    
    paginator = Paginator(folders, 20)
    page = request.GET.get('page')
    folders = paginator.get_page(page)
    
    return render(request, 'folders.html', {'folders': folders})


@login_required 
def images_view(request, folder_id=None): 
    """View for managing images in a folder""" 
    if folder_id: 
        folder = get_object_or_404(Folder, id=folder_id, is_deleted=False) 
         
        # Check permissions 
        if not request.user.is_superuser: 
            if not (folder.created_by == request.user or  
                   UserPermission.objects.filter( 
                       user=request.user,  
                       folder=folder,  
                       permission='view' 
                   ).exists()): 
                messages.error(request, 'You do not have permission to access this folder.') 
                return redirect('folders') 
         
        images = Image.objects.filter(folder=folder, is_deleted=False) 
        
        # Get user permissions for the current folder
        if request.user.is_superuser or folder.created_by == request.user: 
            user_permissions = ['view', 'create', 'update', 'delete', 'download'] 
        else: 
            user_permissions = list(UserPermission.objects.filter( 
                user=request.user, 
                folder=folder 
            ).values_list('permission', flat=True))
            
    else: 
        # Show all images user has access to 
        if request.user.is_superuser: 
            images = Image.objects.filter(is_deleted=False) 
            user_permissions = ['view', 'create', 'update', 'delete', 'download']
        else: 
            permitted_folders = UserPermission.objects.filter( 
                user=request.user 
            ).values_list('folder_id', flat=True) 
             
            images = Image.objects.filter( 
                Q(folder__id__in=permitted_folders) | Q(created_by=request.user), 
                is_deleted=False 
            ).distinct() 
            
            # For all images view, check if user has create permission in any folder
            # or if they have any folders they created
            has_create_permission = (
                UserPermission.objects.filter(
                    user=request.user,
                    permission='create'
                ).exists() or
                Folder.objects.filter(created_by=request.user, is_deleted=False).exists()
            )
            
            user_permissions = []
            if has_create_permission:
                user_permissions.append('create')
            
            # Add other permissions as needed for all images view
            if UserPermission.objects.filter(user=request.user, permission='view').exists():
                user_permissions.append('view')
                
        folder = None 
     
    # Add permissions to each image for individual image operations
    for image in images: 
        if request.user.is_superuser or image.created_by == request.user: 
            image.user_permissions = ['view', 'create', 'update', 'delete', 'download'] 
        else: 
            image.user_permissions = list(UserPermission.objects.filter( 
                user=request.user, 
                folder=image.folder 
            ).values_list('permission', flat=True)) 
     
    paginator = Paginator(images, 20) 
    page = request.GET.get('page') 
    images = paginator.get_page(page) 
     
    return render(request, 'images.html', { 
        'images': images, 
        'folder': folder, 
        'user_permissions': user_permissions, 
    })

# Utility function to log actions
def log_action(user, action, content_type, object_id, object_name, request=None):
    """Log user actions for audit trail"""
    ip_address = None
    user_agent = ''
    
    if request:
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    AuditLog.objects.create(
        user=user,
        action=action,
        content_type=content_type,
        object_id=object_id,
        object_name=object_name,
        ip_address=ip_address,
        user_agent=user_agent
    )

# REST API ViewSets
class FolderViewSet(viewsets.ModelViewSet):
    """ViewSet for Folder CRUD operations"""
    queryset = Folder.objects.filter(is_deleted=False)
    serializer_class = FolderSerializer
    permission_classes = [IsAuthenticated, HasFolderPermission]
    
    def get_queryset(self):
        """Filter folders based on user permissions"""
        if self.request.user.is_superuser:
            return Folder.objects.filter(is_deleted=False)
        
        # Get folders user has permission to access
        permitted_folders = UserPermission.objects.filter(
            user=self.request.user
        ).values_list('folder_id', flat=True)
        
        return Folder.objects.filter(
            Q(id__in=permitted_folders) | Q(created_by=self.request.user),
            is_deleted=False
        ).distinct()
    
    def perform_create(self, serializer):
        """Set created_by field when creating folder"""
        folder = serializer.save(created_by=self.request.user)
        log_action(
            self.request.user, 
            'create', 
            'folder', 
            folder.id, 
            folder.name,
            self.request
        )
    
    def perform_update(self, serializer):
        """Set updated_by field when updating folder"""
        folder = serializer.save(updated_by=self.request.user)
        log_action(
            self.request.user, 
            'update', 
            'folder', 
            folder.id, 
            folder.name,
            self.request
        )
    
    def perform_destroy(self, instance):
        """Soft delete folder - default behavior"""
        instance.soft_delete(self.request.user)
        log_action(
            self.request.user, 
            'soft_delete', 
            'folder', 
            instance.id, 
            instance.name,
            self.request
        )
    
    @action(detail=True, methods=['post'])
    def restore(self, request, pk=None):
        """Restore soft deleted folder (superuser only)"""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can restore folders'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        folder = get_object_or_404(Folder, pk=pk, is_deleted=True)
        folder.restore(request.user)
        log_action(request.user, 'restore', 'folder', folder.id, folder.name, request)
        
        return Response({'message': 'Folder restored successfully'})
    
    @action(detail=True, methods=['delete'])
    def permanent_delete(self, request, pk=None):
        """Permanently delete folder (superuser only)"""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can permanently delete folders'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        folder = get_object_or_404(Folder, pk=pk)
        folder_name = folder.name
        
        # Delete all images in the folder first
        images = Image.objects.filter(folder=folder)
        for image in images:
            if image.image_file:
                image.image_file.delete()
        images.delete()
        
        # Delete all permissions for this folder
        UserPermission.objects.filter(folder=folder).delete()
        
        # Delete the folder
        folder.delete()
        
        log_action(request.user, 'permanent_delete', 'folder', pk, folder_name, request)
        
        return Response({'message': 'Folder permanently deleted'})

class ImageViewSet(viewsets.ModelViewSet):
    """ViewSet for Image CRUD operations"""
    queryset = Image.objects.filter(is_deleted=False)
    serializer_class = ImageSerializer
    permission_classes = [IsAuthenticated, HasFolderPermission]
    
    def get_queryset(self):
        """Filter images based on user permissions"""
        if self.request.user.is_superuser:
            return Image.objects.filter(is_deleted=False)
        
        # Get folders user has permission to access
        permitted_folders = UserPermission.objects.filter(
            user=self.request.user
        ).values_list('folder_id', flat=True)
        
        return Image.objects.filter(
            Q(folder__id__in=permitted_folders) | Q(created_by=self.request.user),
            is_deleted=False
        ).distinct()
    
    def perform_create(self, serializer):
        """Set created_by field when creating image"""
        image = serializer.save(created_by=self.request.user)
        log_action(
            self.request.user, 
            'create', 
            'image', 
            image.id, 
            image.name,
            self.request
        )
    
    def perform_update(self, serializer):
        """Set updated_by field when updating image"""
        image = serializer.save(updated_by=self.request.user)
        log_action(
            self.request.user, 
            'update', 
            'image', 
            image.id, 
            image.name,
            self.request
        )
    
    def perform_destroy(self, instance):
        """Soft delete image - default behavior"""
        instance.soft_delete(self.request.user)
        log_action(
            self.request.user, 
            'soft_delete', 
            'image', 
            instance.id, 
            instance.name,
            self.request
        )
    
    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated, CanDownloadImage])
    def download(self, request, pk=None):
        """Download image file"""
        image = get_object_or_404(Image, pk=pk, is_deleted=False)
        
        if not image.image_file:
            return Response(
                {'error': 'Image file not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        log_action(request.user, 'download', 'image', image.id, image.name, request)
        
        response = HttpResponse(
            image.image_file.read(), 
            content_type=f'image/{image.file_type}'
        )
        response['Content-Disposition'] = f'attachment; filename="{image.name}.{image.file_type}"'
        return response
    
    @action(detail=True, methods=['post'])
    def restore(self, request, pk=None):
        """Restore soft deleted image (superuser only)"""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can restore images'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        image = get_object_or_404(Image, pk=pk, is_deleted=True)
        image.restore(request.user)
        log_action(request.user, 'restore', 'image', image.id, image.name, request)
        
        return Response({'message': 'Image restored successfully'})
    
    @action(detail=True, methods=['delete'])
    def permanent_delete(self, request, pk=None):
        """Permanently delete image (superuser only)"""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can permanently delete images'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        image = get_object_or_404(Image, pk=pk)
        image_name = image.name
        
        # Delete the actual file
        if image.image_file:
            image.image_file.delete()
        
        # Delete the database record
        image.delete()
        
        log_action(request.user, 'permanent_delete', 'image', pk, image_name, request)
        
        return Response({'message': 'Image permanently deleted'})

class UserPermissionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing user permissions (superuser only)"""
    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerializer
    permission_classes = [IsAuthenticated, permissions.IsAdminUser]
    
    def get_queryset(self):
        """Filter permissions based on folder if provided"""
        queryset = UserPermission.objects.all()
        folder_id = self.request.query_params.get('folder', None)
        if folder_id is not None:
            queryset = queryset.filter(folder_id=folder_id)
        return queryset
    
    def perform_create(self, serializer):
        """Set granted_by field when creating permission"""
        # Always set 'view' as default permission if not specified
        permission = self.request.data.get('permission', 'view')
        serializer.save(granted_by=self.request.user, permission=permission)
    
    def create(self, request, *args, **kwargs):
        """Override create to handle duplicate permissions, auto-grant view, and set default"""
        try:
            user_id = request.data.get('user_id')
            folder_id = request.data.get('folder_id')
            permission = request.data.get('permission', 'view')  # Default to 'view'
            
            # Update request data with default permission
            request.data['permission'] = permission
            
            if user_id and folder_id and permission:
                # Check if user already has this specific permission
                existing_permission = UserPermission.objects.filter(
                    user_id=user_id,
                    folder_id=folder_id,
                    permission=permission
                ).first()
                
                if existing_permission:
                    return Response(
                        {'error': f'User already has {permission} permission for this folder'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Auto-grant view permission if granting other permissions
                if permission != 'view':
                    view_permission_exists = UserPermission.objects.filter(
                        user_id=user_id,
                        folder_id=folder_id,
                        permission='view'
                    ).exists()
                    
                    if not view_permission_exists:
                        # Create view permission first
                        UserPermission.objects.create(
                            user_id=user_id,
                            folder_id=folder_id,
                            permission='view',
                            granted_by=request.user
                        )
            
            return super().create(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def update(self, request, *args, **kwargs):
        """Update permission"""
        try:
            permission_obj = self.get_object()
            new_permission = request.data.get('permission', 'view')
            
            # Check if user already has this permission
            existing_permission = UserPermission.objects.filter(
                user=permission_obj.user,
                folder=permission_obj.folder,
                permission=new_permission
            ).exclude(id=permission_obj.id).first()
            
            if existing_permission:
                return Response(
                    {'error': f'User already has {new_permission} permission for this folder'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # If changing from view to another permission, auto-grant view
            if new_permission != 'view':
                view_permission_exists = UserPermission.objects.filter(
                    user=permission_obj.user,
                    folder=permission_obj.folder,
                    permission='view'
                ).exclude(id=permission_obj.id).exists()
                
                if not view_permission_exists:
                    # Create view permission
                    UserPermission.objects.create(
                        user=permission_obj.user,
                        folder=permission_obj.folder,
                        permission='view',
                        granted_by=request.user
                    )
            
            permission_obj.permission = new_permission
            permission_obj.save()
            
            serializer = self.get_serializer(permission_obj)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def destroy(self, request, *args, **kwargs):
        """Override destroy to handle view permission dependency"""
        try:
            permission_obj = self.get_object()
            
            # If deleting view permission, check if user has other permissions
            if permission_obj.permission == 'view':
                other_permissions = UserPermission.objects.filter(
                    user=permission_obj.user,
                    folder=permission_obj.folder
                ).exclude(id=permission_obj.id, permission='view')
                
                if other_permissions.exists():
                    return Response(
                        {'error': 'Cannot remove view permission while user has other permissions. Remove other permissions first.'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            return super().destroy(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing audit logs"""
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter audit logs based on user permissions"""
        if self.request.user.is_superuser:
            return AuditLog.objects.all()
        return AuditLog.objects.filter(user=self.request.user)

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for listing users (superuser only)"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, permissions.IsAdminUser]
    
    def get_queryset(self):
        """Filter users based on context"""
        queryset = User.objects.filter(is_active=True)
        folder_id = self.request.query_params.get('folder_id')
        
        if folder_id:
            try:
                folder = Folder.objects.get(id=folder_id)
                # Exclude folder creator and superusers
                excluded_users = [folder.created_by.id] if folder.created_by else []
                superuser_ids = User.objects.filter(is_superuser=True).values_list('id', flat=True)
                excluded_users.extend(superuser_ids)
                
                queryset = queryset.exclude(id__in=excluded_users)
            except Folder.DoesNotExist:
                pass
        
        return queryset

# AJAX Views for frontend
@login_required
@csrf_exempt
def create_folder_ajax(request):
    """Create folder via AJAX"""
    if request.method == 'POST':
        data = json.loads(request.body)
        name = data.get('name')
        description = data.get('description', '')
        parent_id = data.get('parent_id')
        
        if not name:
            return JsonResponse({'error': 'Folder name is required'}, status=400)
        
        try:
            parent = None
            if parent_id:
                parent = Folder.objects.get(id=parent_id, is_deleted=False)
            
            folder = Folder.objects.create(
                name=name,
                description=description,
                parent=parent,
                created_by=request.user
            )
            
            log_action(request.user, 'create', 'folder', folder.id, folder.name, request)
            
            return JsonResponse({
                'success': True,
                'folder': {
                    'id': folder.id,
                    'name': folder.name,
                    'description': folder.description,
                    'created_at': folder.created_at.isoformat()
                }
            })
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
@csrf_exempt
def upload_image_ajax(request):
    """Upload image via AJAX"""
    if request.method == 'POST':
        folder_id = request.POST.get('folder_id')
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        image_file = request.FILES.get('image_file')
        
        if not all([folder_id, name, image_file]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        try:
            folder = Folder.objects.get(id=folder_id, is_deleted=False)
            
            # Check permissions
            if not request.user.is_superuser:
                if not (folder.created_by == request.user or 
                       UserPermission.objects.filter(
                           user=request.user, 
                           folder=folder, 
                           permission='create'
                       ).exists()):
                    return JsonResponse({'error': 'Permission denied'}, status=403)
            
            # Check if image with same name exists in folder
            if Image.objects.filter(name=name, folder=folder, is_deleted=False).exists():
                return JsonResponse({'error': 'Image with this name already exists in folder'}, status=400)
            
            image = Image.objects.create(
                name=name,
                description=description,
                folder=folder,
                image_file=image_file,
                created_by=request.user
            )
            
            log_action(request.user, 'create', 'image', image.id, image.name, request)
            
            return JsonResponse({
                'success': True,
                'image': {
                    'id': image.id,
                    'name': image.name,
                    'description': image.description,
                    'file_size': image.file_size,
                    'file_type': image.file_type,
                    'created_at': image.created_at.isoformat()
                }
            })
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
@require_http_methods(["DELETE"])
def delete_folder_ajax(request, folder_id):
    """Delete folder via AJAX with superuser options"""
    try:
        folder = Folder.objects.get(id=folder_id, is_deleted=False)
        
        # Check permissions
        if not request.user.is_superuser:
            if not (folder.created_by == request.user or 
                   UserPermission.objects.filter(
                       user=request.user, 
                       folder=folder, 
                       permission='delete'
                   ).exists()):
                return JsonResponse({'error': 'Permission denied'}, status=403)
        
        # Check if this is a permanent delete request (superuser only)
        permanent = request.GET.get('permanent', 'false').lower() == 'true'
        
        if permanent and request.user.is_superuser:
            # Permanent delete
            folder_name = folder.name
            
            # Delete all images in the folder first
            images = Image.objects.filter(folder=folder)
            for image in images:
                if image.image_file:
                    image.image_file.delete()
            images.delete()
            
            # Delete all permissions for this folder
            UserPermission.objects.filter(folder=folder).delete()
            
            # Delete the folder
            folder.delete()
            
            log_action(request.user, 'permanent_delete', 'folder', folder_id, folder_name, request)
            
            return JsonResponse({'success': True, 'message': 'Folder permanently deleted'})
        else:
            # Soft delete
            folder.soft_delete(request.user)
            log_action(request.user, 'soft_delete', 'folder', folder.id, folder.name, request)
            
            return JsonResponse({'success': True, 'message': 'Folder deleted'})
    
    except Folder.DoesNotExist:
        return JsonResponse({'error': 'Folder not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["DELETE"])
def delete_image_ajax(request, image_id):
    """Delete image via AJAX with superuser options"""
    try:
        image = Image.objects.get(id=image_id, is_deleted=False)
        
        # Check permissions
        if not request.user.is_superuser:
            if not (image.created_by == request.user or 
                   UserPermission.objects.filter(
                       user=request.user, 
                       folder=image.folder, 
                       permission='delete'
                   ).exists()):
                return JsonResponse({'error': 'Permission denied'}, status=403)
        
        # Check if this is a permanent delete request (superuser only)
        permanent = request.GET.get('permanent', 'false').lower() == 'true'
        
        if permanent and request.user.is_superuser:
            # Permanent delete
            image_name = image.name
            
            # Delete the actual file
            if image.image_file:
                image.image_file.delete()
            
            # Delete the database record
            image.delete()
            
            log_action(request.user, 'permanent_delete', 'image', image_id, image_name, request)
            
            return JsonResponse({'success': True, 'message': 'Image permanently deleted'})
        else:
            # Soft delete
            image.soft_delete(request.user)
            log_action(request.user, 'soft_delete', 'image', image.id, image.name, request)
            
            return JsonResponse({'success': True, 'message': 'Image deleted'})
    
    except Image.DoesNotExist:
        return JsonResponse({'error': 'Image not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@csrf_exempt
def update_permission_ajax(request, permission_id):
    """Update user permission via AJAX"""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            permission = data.get('permission', 'read')
            
            permission_obj = UserPermission.objects.get(id=permission_id)
            
            # Check if user already has this permission
            existing_permission = UserPermission.objects.filter(
                user=permission_obj.user,
                folder=permission_obj.folder,
                permission=permission
            ).exclude(id=permission_obj.id).first()
            
            if existing_permission:
                return JsonResponse({
                    'error': f'User already has {permission} permission for this folder'
                }, status=400)
            
            permission_obj.permission = permission
            permission_obj.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Permission updated successfully',
                'permission': {
                    'id': permission_obj.id,
                    'permission': permission_obj.permission,
                    'user': permission_obj.user.username,
                    'folder': permission_obj.folder.name
                }
            })
            
        except UserPermission.DoesNotExist:
            return JsonResponse({'error': 'Permission not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
    