from django.contrib import admin

# Register your models here.
from django.contrib import admin
from django.utils.html import format_html
from .models import Folder, Image, UserPermission, AuditLog

@admin.register(Folder)
class FolderAdmin(admin.ModelAdmin):
    list_display = ['name', 'parent', 'created_by', 'created_at', 'is_deleted']
    list_filter = ['created_at', 'is_deleted', 'created_by']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at', 'deleted_at']
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'parent')
        }),
        ('Audit Information', {
            'fields': ('created_by', 'updated_by', 'deleted_by', 'created_at', 'updated_at', 'deleted_at', 'is_deleted'),
            'classes': ('collapse',)
        }),
    )

@admin.register(Image)
class ImageAdmin(admin.ModelAdmin):
    list_display = ['name', 'folder', 'file_type', 'file_size_display', 'created_by', 'created_at', 'is_deleted']
    list_filter = ['created_at', 'is_deleted', 'file_type', 'folder']
    search_fields = ['name', 'description', 'folder__name']
    readonly_fields = ['created_at', 'updated_at', 'deleted_at', 'file_size', 'file_type']
    
    def file_size_display(self, obj):
        if obj.file_size:
            if obj.file_size < 1024:
                return f"{obj.file_size} B"
            elif obj.file_size < 1024 * 1024:
                return f"{obj.file_size / 1024:.1f} KB"
            else:
                return f"{obj.file_size / (1024 * 1024):.1f} MB"
        return "N/A"
    file_size_display.short_description = 'File Size'
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'folder', 'image_file')
        }),
        ('File Information', {
            'fields': ('file_size', 'file_type'),
            'classes': ('collapse',)
        }),
        ('Audit Information', {
            'fields': ('created_by', 'updated_by', 'deleted_by', 'created_at', 'updated_at', 'deleted_at', 'is_deleted'),
            'classes': ('collapse',)
        }),
    )

@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ['user', 'folder', 'permission', 'granted_by', 'granted_at']
    list_filter = ['permission', 'granted_at', 'granted_by']
    search_fields = ['user__username', 'folder__name']
    
    fieldsets = (
        (None, {
            'fields': ('user', 'folder', 'permission')
        }),
        ('Grant Information', {
            'fields': ('granted_by', 'granted_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'content_type', 'object_name', 'timestamp']
    list_filter = ['action', 'content_type', 'timestamp']
    search_fields = ['user__username', 'object_name']
    readonly_fields = ['user', 'action', 'content_type', 'object_id', 'object_name', 'timestamp', 'ip_address', 'user_agent']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False