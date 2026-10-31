from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('', views.notifications_list, name='list'),
    path('read/<int:pk>/', views.mark_as_read, name='mark_read'),
    path('read-all/', views.mark_all_read, name='mark_all_read'),
    path('delete/<int:pk>/', views.delete_notification, name='delete'),
]
