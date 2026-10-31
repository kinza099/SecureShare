from django.urls import path
from . import views

app_name = 'filemanager'

urlpatterns = [
    path('upload/', views.upload_view, name='upload'),
    path('my-files/', views.my_files_view, name='my_files'),
    path('details/<uuid:pk>/', views.file_details_view, name='details'),
    path('download/<uuid:pk>/', views.download_file_view, name='download'),
    path('preview/<uuid:pk>/', views.preview_file_view, name='preview'),
    path('rename/<uuid:pk>/', views.rename_file_view, name='rename'),
    path('delete/<uuid:pk>/', views.delete_file_view, name='delete'),
    path('upload-version/<uuid:pk>/', views.upload_version_view, name='upload_version'),
    path('versions/<uuid:pk>/', views.version_history_view, name='version_history'),
]
