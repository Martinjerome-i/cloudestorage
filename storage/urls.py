from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# API Router
router = DefaultRouter()
router.register(r'folders', views.FolderViewSet)
router.register(r'images', views.ImageViewSet)
router.register(r'permissions', views.UserPermissionViewSet)
router.register(r'audit-logs', views.AuditLogViewSet)

urlpatterns = [
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main Views
    path('', views.dashboard, name='dashboard'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('folders/', views.folders_view, name='folders'),
    path('images/', views.images_view, name='images'),
    path('images/folder/<int:folder_id>/', views.images_view, name='folder_images'),
    
    # AJAX endpoints
    path('ajax/create-folder/', views.create_folder_ajax, name='create_folder_ajax'),
    path('ajax/upload-image/', views.upload_image_ajax, name='upload_image_ajax'),
    path('ajax/delete-folder/<int:folder_id>/', views.delete_folder_ajax, name='delete_folder_ajax'),
    path('ajax/delete-image/<int:image_id>/', views.delete_image_ajax, name='delete_image_ajax'),
    
    # API URLs
    path('api/v1/', include(router.urls)),
]
