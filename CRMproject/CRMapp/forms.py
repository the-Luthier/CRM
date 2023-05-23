import os
import sys

project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_dir)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'NetGmobile.settings')

import django
django.setup()


from django import forms
from django.contrib.auth.forms import UserCreationForm 
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm as BasePasswordResetForm
from .models import Profile
from django.contrib.auth import authenticate, get_user_model




class LoginForm(AuthenticationForm):
    phone_number = forms.CharField(max_length=20, required=True, help_text='Phone number')
    
    class Meta:
        model = get_user_model()
        fields = ('phone_number', 'password')



class SignUpForm(UserCreationForm):
    phone_number = forms.CharField(max_length=20, required=True, help_text='Phone number')
    username = forms.CharField(max_length=11, required=True, help_text='Username')
    password = forms.CharField(max_length=20, required=True, help_text='Password')
    password_again = forms.CharField(max_length=20, required=True, help_text='Password again')

    class Meta:
        model = get_user_model()
        fields = ('username', 'phone_number', 'password', 'password_again')



class VerifyForm(forms.Form):
    code = forms.CharField(max_length=6, required=True, help_text='Enter code')

    class Meta:
        model = get_user_model()
        fields = ('code',)
    
    
    
class PasswordResetForm(BasePasswordResetForm):
    phone_number = forms.CharField(max_length=20, required=True, help_text='Phone number')
    
    class Meta:
        model = get_user_model()
        fields = ('phone_number')



class PasswordChangeForm(forms.Form):
    password = forms.CharField(max_length=20, required=True, help_text='Old password')
    new_password1 = forms.CharField(max_length=20, required=True, help_text='New password')
    new_password2 = forms.CharField(max_length=20, required=True, help_text='New password again')
    
    
    class Meta:
        model = get_user_model()
        fields = ('password', 'new_password1', 'new_password2')
        
        
        
class UserInfoForm(forms.Form):
    user_name = forms.CharField(max_length=11, required=True, help_text='Username') 
    phone = forms.CharField(min_length=10, required=True, help_text='5XXXXXXXX')  
    email = forms.CharField(max_length=100, required=False, help_text='Email')
    adress = forms.CharField(max_length=250, required=True, help_text='Adress')
    
    class Meta:
        model = get_user_model()
        fields = ('username', 'phone_number', 'email', 'adress', 'address', 'first_name', 'last_name',)