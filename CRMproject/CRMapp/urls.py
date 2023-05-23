from django.urls import path, re_path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('api/main/', views.index, name='index'),       
    path('api/login/', views.login, name='login'),         
    path('api/signup/', views.signup, name='signup'),         
    path('api/verify_code/', views.verify_code, name='verify_code'),      
    path('api/welcome/', views.welcome, name='welcome'),         
    path('api/user_profile/', views.UserDetailUpdateView.as_view(), name='user_profile'),      
    path('api/user_info/', views.UserDetailUpdateView.as_view(), name='user_info'),       
    path('api/change_password/', views.change_password, name='change_password'),       
    path('api/user_info_update/', views.UserDetailUpdateView.as_view(), name='user_info_update'),     
    path('api/forgot_password/', views.forgot_password, name='forgot_password'),  
    path('api/new_password/', views.new_password, name='new_password'),      
    path('api/special/', views.special, name='special'),
    path('api/support/', views.support, name='support'),
    path('api/faq/', views.faq, name='faq'),
    path('api/contact/', views.contact_us, name='contact_us'),
    path('api/packages/', views.packages, name='packages'),
    path('api/development/', views.development, name='development'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
]
