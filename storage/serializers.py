from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Folder, Image, UserPermission, AuditLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser']
        read_only_fields = ['id', 'is_staff', 'is_superuser']

class FolderSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    updated_by = UserSerializer(read_only=True)
    children = serializers.SerializerMethodField()
    image_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Folder
        fields = ['id', 'name', 'description', 'parent', 'created_by', 'updated_by', 
                 'created_at', 'updated_at', 'is_deleted', 'children', 'image_count']
        read_only_fields = ['id', 'created_by', 'updated_by', 'created_at', 'updated_at']
    
    def get_children(self, obj):
        if obj.children.filter(is_deleted=False).exists():
            return FolderSerializer(obj.children.filter(is_deleted=False), many=True).data
        return []
    
    def get_image_count(self, obj):
        return obj.images.filter(is_deleted=False).count()

class ImageSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    updated_by = UserSerializer(read_only=True)
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    
    class Meta:
        model = Image
        fields = ['id', 'name', 'description', 'folder', 'folder_name', 'image_file', 
                 'file_size', 'file_type', 'created_by', 'updated_by', 'created_at', 
                 'updated_at', 'is_deleted']
        read_only_fields = ['id', 'file_size', 'file_type', 'created_by', 'updated_by', 
                           'created_at', 'updated_at']

class UserPermissionSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    folder = FolderSerializer(read_only=True)
    granted_by = UserSerializer(read_only=True)
    
    class Meta:
        model = UserPermission
        fields = ['id', 'user', 'folder', 'permission', 'granted_by', 'granted_at']
        read_only_fields = ['id', 'granted_by', 'granted_at']

class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'action', 'content_type', 'object_id', 'object_name', 
                 'timestamp', 'ip_address', 'user_agent']
        read_only_fields = ['id', 'user', 'timestamp']