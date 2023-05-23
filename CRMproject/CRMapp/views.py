from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login as django_login
from .forms import SignUpForm, VerifyForm, LoginForm, PasswordResetForm, UserInfoForm, PasswordChangeForm
from .decorators import verification_required
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from .serializers import ForgotPasswordSerializer, SignupSerializer, UserSerializer, ProfileSerializer, FileErrorSerializer, NotificationsSerializer, SubscriptionsSerializer, PasswordSerializer
from . import verify
from .models import  FileError, Notifications, Subscriptions, Profile


# Create your views here.

@api_view(['POST'])
def login(request):  
    form = LoginForm(request.POST)    
    if request.method == 'POST':
        username = Profile.objects.get('username')
        password = request.data.get('password')
        phone_number = Profile.objects.get('phone_number')
        
        if not (username and password and phone_number):
            return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(request, username=username, password=password)
        
        if Profile is not None:
            verify.send(phone_number)
            # Store user ID in the session or use a token-based authentication system (e.g., JWT)
            request.session['user_id'] = Profile.id
            return Response({'message': 'Verification code sent'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



@api_view(['GET'])
@login_required
@verification_required
@permission_classes([IsAuthenticated])
def index(request): 
  if Profile is not None:
    return render(request, 'homepage')
  if Profile.is_authenticated and Profile.is_verified:
    return render(request, 'homepage')
  else:
    return render(request, 'login')


@api_view(['POST'])
def signup(request):       
    if request.method == 'POST':
        serializer = SignupSerializer(request.POST)
        if serializer.is_valid():
          if Profile is not None:
            serializer.save()
            verify.send(serializer.phone_number)
            return redirect('verify_code')
    else :
     return render(request, 'signup.dart')
    
               
@api_view(['POST'])        
@login_required
def verify_code(request):    
    if request.method == 'POST':
        form = VerifyForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('code')
            if verify.check(Profile.phone_number, code):
                Profile.is_verified = True
                request.user.save()
                return redirect('index')
    else:
        form = VerifyForm()
    return redirect(request, 'verify_code')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def welcome(request):  
  if Profile is not None:
    return redirect('user_info_update')
  else:
    return redirect('signup')
  


@api_view(['POST'])
@verification_required
def forgot_password(request):       
    if request.method == 'POST':
        serializer = ForgotPasswordSerializer(request.POST)
        if serializer.is_valid():
          if Profile is not None:
            serializer.save()
            verify.send(serializer.phone_number)
            return redirect('new_password')
    else :
      return render(request, 'forgot_password')
    


@api_view(['POST'])
@verification_required
def new_password(request):       
    if request.method == 'POST':
          if Profile is not None:
            return redirect('login')
    else :
      return render(request, 'new_password.dart')
  
  
      
        
class UserDetailUpdateView(generics.RetrieveUpdateAPIView):  
  queryset = Profile.objects.all()
  serializer = ProfileSerializer

  def get_object(self):
    return self.request.user

  def update(self, request, *args, **kwargs):
    instance = self.get_object()
    serializer = UserSerializer(request.POST)
    if serializer.is_valid():     
      serializer.is_valid(raise_exception=False) 
      self.get_serializer(instance, data=request.data, partial=True)      
      self.perform_update(serializer)
    return Response(UserSerializer.data)
  
  
    
@api_view(['POST'])
@verification_required
@login_required
def change_password(request):  
    if request.method == 'POST':
        serializer = PasswordSerializer(data=request.POST)
        if serializer.is_valid():            
            user = authenticate(request, username=Profile.full_name, password=request.data['password1'])
            if user is not None:
                password = request.data['password1']
                user.set_password(password)
                user.save()
                login(request)
                messages.success(request, 'Your password was successfully updated!')
                
            else:
                messages.error(request, 'Invalid current password')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        serializer = UserSerializer()

    return render(request, 'change_password', {'serializer': serializer})


@permission_classes([IsAuthenticated])
class FileErrorListCreateView(generics.ListCreateAPIView):
    serializer_class = FileErrorSerializer

    def get_queryset(self):
        return FileError.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)



@permission_classes([IsAuthenticated])  
class NotificationsListCreateView(generics.ListCreateAPIView):
    serializer_class = NotificationsSerializer

    def get_queryset(self):
        return Notifications.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)    


@permission_classes([IsAuthenticated])
class SubscriptionsListCreateView(generics.ListCreateAPIView):
    serializer_class = SubscriptionsSerializer

    def get_queryset(self):
        return Subscriptions.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


  
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def services(request):  
  return redirect(request, 'services')
  
  
  

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def special(request):    
    return redirect(request, 'special')

  
@api_view(['GET'])  
@login_required
def packages(request):    
    return redirect(request, 'packages')
  
  
@api_view(['GET'])
def support(request):  
  return render(request, 'support.dart')   


@api_view(['GET'])
def faq(request):    
  return render(request, 'faq.dart')


@api_view(['POST'])
@login_required
def contact_us(request):  
  return render(request, 'contact_us.dart')


@api_view(['GET'])
def development(request):  
  return render(request, 'development.dart')


def logout(request):
  return redirect(request, 'login')