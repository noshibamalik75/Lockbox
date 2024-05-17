# urls.py

from django.urls import path
from . import views
from .views import FileEncryptView, FileDecryptView

urlpatterns = [
    path('',views.index ,name='index'),
    path('files/', views.file_list, name='file_list'),
    path('security_keys/', views.security_key_list, name='security_key_list'),
    path('upload_file',views.upload_file, name='upload_file'),
    path('delete_files/', views.delete_files, name='delete_files'),
    path('manage_access/<int:file_id>/', views.manage_access, name='manage_access'),
    path('manage_access_settings/<int:file_id>/', views.manage_access_settings, name='manage_access_settings'),
    path('login/', views.Login, name='login'),
    path('signup/', views.SignUp, name='signup'),
    path('logout/', views.Logout, name='logout'),
    path('encrypt/', FileEncryptView.as_view(), name='file_encrypt'),
    path('decrypt/<int:pk>/', FileDecryptView.as_view(), name='file_decrypt'),
]