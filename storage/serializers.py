from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Folder, Image, UserPermission, AuditLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_superuser']

class FolderSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    updated_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Folder
        fields = ['id', 'name', 'description', 'parent', 'created_by', 'updated_by', 
                 'created_at', 'updated_at', 'is_deleted']
        read_only_fields = ['created_by', 'updated_by', 'created_at', 'updated_at']

class ImageSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    updated_by = UserSerializer(read_only=True)
    folder = FolderSerializer(read_only=True)
    folder_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = Image
        fields = ['id', 'name', 'description', 'folder', 'folder_id', 'image_file', 
                 'file_size', 'file_type', 'created_by', 'updated_by', 
                 'created_at', 'updated_at', 'is_deleted']
        read_only_fields = ['created_by', 'updated_by', 'created_at', 'updated_at', 
                           'file_size', 'file_type']

class UserPermissionSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    user_id = serializers.IntegerField(write_only=True)
    folder = FolderSerializer(read_only=True)
    folder_id = serializers.IntegerField(write_only=True)
    granted_by = UserSerializer(read_only=True)
    available_users = serializers.SerializerMethodField()
    
    class Meta:
        model = UserPermission
        fields = ['id', 'user', 'user_id', 'folder', 'folder_id', 'permission', 
                 'granted_by', 'granted_at', 'available_users']
        read_only_fields = ['granted_by', 'granted_at']
    
    def get_available_users(self, obj):
        """Get users excluding folder creator and superusers when admin manages permissions"""
        request = self.context.get('request')
        if request and request.user.is_superuser:
            folder = obj.folder if hasattr(obj, 'folder') else None
            if folder:
                # Exclude folder creator and superusers
                excluded_users = [folder.created_by.id] if folder.created_by else []
                superuser_ids = User.objects.filter(is_superuser=True).values_list('id', flat=True)
                excluded_users.extend(superuser_ids)
                
                available_users = User.objects.filter(
                    is_active=True
                ).exclude(id__in=excluded_users)
                
                return UserSerializer(available_users, many=True).data
        return []
    
    def create(self, validated_data):
        user_id = validated_data.pop('user_id')
        folder_id = validated_data.pop('folder_id')
        
        # Get the actual User and Folder instances
        user = User.objects.get(id=user_id)
        folder = Folder.objects.get(id=folder_id)
        
        # Create the UserPermission with the actual instances
        return UserPermission.objects.create(
            user=user,
            folder=folder,
            **validated_data
        )

class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'action', 'content_type', 'object_id', 'object_name', 
                 'timestamp', 'ip_address', 'user_agent']
        