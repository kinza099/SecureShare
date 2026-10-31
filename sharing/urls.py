from django.urls import path
from . import views

app_name = 'sharing'

urlpatterns = [
    path('share/<uuid:pk>/', views.share_file_view, name='share_file'),
    path('revoke-share/<uuid:pk>/', views.revoke_share_view, name='revoke_share'),
    path('create-link/<uuid:pk>/', views.create_link_view, name='create_link'),
    path('links/', views.sharing_links_list_view, name='sharing_links'),
    path('revoke-link/<uuid:pk>/', views.revoke_link_view, name='revoke_link'),
    path('qr/<str:token>/', views.qr_code_view, name='qr_code'),
    path('access/<str:token>/', views.access_link_view, name='access_link'),
    path('received/', views.received_files_view, name='received_files'),
]
