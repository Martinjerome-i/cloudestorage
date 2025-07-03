from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import os

class BaseModel(models.Model):
    """Base model with audit fields"""
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='%(class)s_created')
    updated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='%(class)s_updated', null=True, blank=True)
    deleted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='%(class)s_deleted', null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    is_deleted = models.BooleanField(default=False)
    
    class Meta:
        abstract = True
    
    def soft_delete(self, user):
        """Soft delete the object"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = user
        self.save()
    
    def restore(self, user):
        """Restore soft deleted object"""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.updated_by = user
        self.save()

class Folder(BaseModel):
    """Folder model for organizing images"""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    
    class Meta:
        unique_together = ['name', 'parent', 'created_by']
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def get_full_path(self):
        """Get full path of the folder"""
        if self.parent:
            return f"{self.parent.get_full_path()}/{self.name}"
        return self.name

class Image(BaseModel):
    """Image model for storing images"""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='images')
    image_file = models.ImageField(upload_to='uploads/')
    file_size = models.BigIntegerField()
    file_type = models.CharField(max_length=50)
    
    class Meta:
        unique_together = ['name', 'folder']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.folder.name}"
    
    def save(self, *args, **kwargs):
        if self.image_file:
            self.file_size = self.image_file.size
            self.file_type = self.image_file.name.split('.')[-1].lower()
        super().save(*args, **kwargs)
    
    def delete(self, using=None, keep_parents=False):
        """Override delete to remove file from filesystem"""
        if self.image_file:
            if os.path.isfile(self.image_file.path):
                os.remove(self.image_file.path)
        super().delete(using, keep_parents)

class UserPermission(models.Model):
    """User permissions for folders"""
    PERMISSION_CHOICES = [
        ('read', 'Read'),
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('download', 'Download'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES)
    granted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='permissions_granted')
    granted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'folder', 'permission']
    
    def __str__(self):
        return f"{self.user.username} - {self.folder.name} - {self.permission}"

class AuditLog(models.Model):
    """Audit log for tracking user actions"""
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('read', 'Read'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('download', 'Download'),
        ('restore', 'Restore'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    content_type = models.CharField(max_length=50)  # 'folder' or 'image'
    object_id = models.IntegerField()
    object_name = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.username} {self.action} {self.content_type} {self.object_name}"