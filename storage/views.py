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
from .serializers import FolderSerializer, ImageSerializer, UserPermissionSerializer, AuditLogSerializer
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
                       permission='read'
                   ).exists()):
                messages.error(request, 'You do not have permission to access this folder.')
                return redirect('folders')
        
        images = Image.objects.filter(folder=folder, is_deleted=False)
    else:
        # Show all images user has access to
        if request.user.is_superuser:
            images = Image.objects.filter(is_deleted=False)
        else:
            permitted_folders = UserPermission.objects.filter(
                user=request.user
            ).values_list('folder_id', flat=True)
            
            images = Image.objects.filter(
                Q(folder__id__in=permitted_folders) | Q(created_by=request.user),
                is_deleted=False
            ).distinct()
        
        folder = None
    
    paginator = Paginator(images, 20)
    page = request.GET.get('page')
    images = paginator.get_page(page)
    
    return render(request, 'images.html', {
        'images': images,
        'folder': folder,
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
        """Soft delete folder"""
        instance.soft_delete(self.request.user)
        log_action(
            self.request.user, 
            'delete', 
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
        folder.delete()
        log_action(request.user, 'delete', 'folder', pk, folder_name, request)
        
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
        """Soft delete image"""
        instance.soft_delete(self.request.user)
        log_action(
            self.request.user, 
            'delete', 
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
        image.delete()
        log_action(request.user, 'delete', 'image', pk, image_name, request)
        
        return Response({'message': 'Image permanently deleted'})

class UserPermissionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing user permissions (superuser only)"""
    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerializer
    permission_classes = [IsAuthenticated, permissions.IsAdminUser]
    
    def perform_create(self, serializer):
        """Set granted_by field when creating permission"""
        serializer.save(granted_by=self.request.user)

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
    """Delete folder via AJAX"""
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
        
        folder.soft_delete(request.user)
        log_action(request.user, 'delete', 'folder', folder.id, folder.name, request)
        
        return JsonResponse({'success': True})
    
    except Folder.DoesNotExist:
        return JsonResponse({'error': 'Folder not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["DELETE"])
def delete_image_ajax(request, image_id):
    """Delete image via AJAX"""
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
        
        image.soft_delete(request.user)
        log_action(request.user, 'delete', 'image', image.id, image.name, request)
        
        return JsonResponse({'success': True})
    
    except Image.DoesNotExist:
        return JsonResponse({'error': 'Image not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)