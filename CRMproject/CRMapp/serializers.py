import os

from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, get_user_model
from django.utils.crypto import get_random_string
from twilio.rest import Client
from .models import Profile, FileError, Notifications, Subscriptions, User
from .forms import PasswordChangeForm, UserInfoForm, PasswordResetForm, LoginForm, VerifyForm, SubscriptionsForm, FileErrorForm
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    phone_number = serializers.CharField(required=True, write_only=True)
    verification_code = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ['phone_number', 'verification_code']

    def create(self, validated_data):
        phone_number = validated_data['phone_number']
        verification_code = validated_data['verification_code']

        # Generate a random 6-digit verification code
        generated_code = get_random_string(length=6)

        # Save the verification code in the user's profile
        user_profile = Profile.objects.get(phone_number=phone_number)
        user_profile.verification_code = generated_code
        user_profile.save()

        # Send the verification code via Twilio SMS
        twilio_account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        twilio_auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        twilio_phone_number = os.getenv("TWILIO_PHONE_NUMBER")
        client = Client(twilio_account_sid, twilio_auth_token)
        message = client.messages.create(
            body=f'Your verification code is: {generated_code}',
            from_=twilio_phone_number,
            to=phone_number
        )

        # Check if the entered verification code matches the generated one
        if verification_code == generated_code:            
            user = User.objects.create(**validated_data)
            return user
        else:
            raise serializers.ValidationError('Invalid verification code')
        



class ProfileSerializer(serializers.ModelSerializer):
    profile = UserSerializer(required=True)

    class Meta:
        model = Profile
        fields = ['id', 'password', 'email', 'phone_number', 'first_name', 'last_name', 'address', 'profile']

    def create(self, validated_data):
        profile_data = validated_data.pop('profile')
        user = User.objects.create_user(**validated_data)  

        # Create a Profile instance for the user and save the phone number
        Profile.objects.create(user=user, phone_number=profile_data['phone_number'])

        return user

    def validate(self, data):
        id = data.get('id', None)
        password = data.get('password', None)

        if not id:
            raise serializers.ValidationError('ID is required')
        if not password:
            raise serializers.ValidationError('Password is required')

        user = authenticate(username=id, password=password)
        if not user:
            raise serializers.ValidationError('Invalid username/password')

        # Check if the verification code is correct
        profile = Profile.objects.get(user=user)
        if profile.verification_code != data['profile']['verification_code']:
            raise serializers.ValidationError('Incorrect verification code')

        return data
    
    def get_queryset(self):
        user = self.context['request'].user
        queryset = Profile.objects.filter(user=user)
        return queryset



class SignupSerializer(serializers.Serializer):
    id = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    email = serializers.CharField(required=True)
    phone_number = serializers.CharField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    address = serializers.CharField(required=True)
    verification_code = serializers.CharField(required=True)

    def validate(self, data):
        user = serializers.HiddenField(default=serializers.CurrentUserDefault())
        user = data.get('id', None)
        password = data.get('password', None)
        password2 = data.get('password2', None)        
        phone_number = data.get('phone_number', None)
        first_name = data.get('first_name', None)
        last_name = data.get('last_name', None)        
        verification_code = data.get('verification_code', None)

        if not user:
            raise serializers.ValidationError('Username is required')
        if not password:
            raise serializers.ValidationError('Password is required')
        if password != password2:
            raise serializers.ValidationError('Passwords do not match')
        if not phone_number:
            raise serializers.ValidationError('Phone number is required')
        if not first_name:
            raise serializers.ValidationError('First name is required')
        if not last_name:
            raise serializers.ValidationError('Last name is required')        
        if not verification_code:
            raise serializers.ValidationError('Verification code is required')

        # Check if the verification code is correct
        profile = Profile.objects.get(phone_number=phone_number)
        if profile.verification_code != verification_code:
            raise serializers.ValidationError('Incorrect verification code')

        return data

    def create(self, validated_data):
        username = validated_data['username']
        password = validated_data['password']
        email = validated_data['email']
        phone_number = validated_data['phone_number']
        first_name = validated_data['first_name']
        last_name = validated_data['last_name']
        address = validated_data['address']

        user = User.objects.create_user(username=username, password=password, email=email, first_name=first_name, last_name=last_name, address=address)
        profile = Profile.objects.create(user=user, phone_number=phone_number)

        return user


class PasswordSerializer(serializers.Serializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    password = serializers.CharField(max_length=128, write_only=True)
    new_password1 = serializers.CharField(max_length=128, write_only=True)
    new_password2 = serializers.CharField(max_length=128, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        new_password1 = attrs.get('new_password1')
        new_password2 = attrs.get('new_password2')
        verification_code = attrs.get('verification_code')

        if not password:
            raise serializers.ValidationError('Current password is required')
        if not new_password1:
            raise serializers.ValidationError('New password is required')
        if not new_password2:
            raise serializers.ValidationError('New password confirmation is required')
        if new_password1 != new_password2:
            raise serializers.ValidationError('New passwords do not match')

        user = self.context.get('user')
        if not authenticate(username=Profile.id, password=password):
            raise serializers.ValidationError('Current password is incorrect')

        try:
            profile = Profile.objects.get(user=user)
        except Profile.DoesNotExist:
            raise serializers.ValidationError('Profile not found')

        if verification_code != profile.verification_code:
            raise serializers.ValidationError('Verification code is incorrect')

        return attrs

    def save(self, **kwargs):
        user = self.context.get('user')
        if user:
            old_password = self.validated_data.get('old_password')
            if user.check_password(old_password):
                new_password1 = self.validated_data.get('new_password1')
                new_password2 = self.validated_data.get('new_password2')
                if new_password1 == new_password2:
                    user.set_password(new_password1)
                    user.save()
                else:
                    raise serializers.ValidationError('New passwords do not match')
            else:
                raise serializers.ValidationError('Current password is incorrect')
        else:
            raise serializers.ValidationError('User not found')

        try:
            profile = Profile.objects.get(user=user)
        except Profile.DoesNotExist:
            raise serializers.ValidationError('Profile not found')

        profile.verification_code = get_random_string(length=6)
        profile.save()


class ForgotPasswordSerializer(serializers.Serializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    phone_number = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        phone_number = data.get('phone_number', None)
        new_password1 = data.get('new_password1', None)
        new_password2 = data.get('new_password2', None)

        if not phone_number:
            raise serializers.ValidationError('Phone number is required')
        if not new_password1:
            raise serializers.ValidationError('New password is required')
        if not new_password2:
            raise serializers.ValidationError('Confirm new password is required')
        if new_password1 != new_password2:
            raise serializers.ValidationError('New passwords do not match')

        try:
            profile = Profile.objects.get(phone_number=phone_number)
        except Profile.DoesNotExist:
            raise serializers.ValidationError('Profile not found')

        data['profile'] = profile  # Include the profile in the validated data
        return data

    def save(self, **kwargs):
        profile = self.validated_data['profile']
        new_password = self.validated_data['new_password1']

        # Create an instance of your custom PasswordResetForm
        form = PasswordResetForm(data=self.initial_data)
        form.is_valid()

        # Reset the password using the custom form
        form.save()

        # Generate and save a verification code
        profile.verification_code = get_random_string(length=6)
        profile.save()



class FileErrorSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = FileError
        fields = ['id', 'user', 'title', 'description', 'created_at']
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        user = self.context['request'].user
        file_error = FileError.objects.create(user=user, **validated_data)
        return file_error
    
    def get_queryset(self):
        user = self.context['request'].user
        queryset = FileError.objects.filter(user=user)
        return queryset
    
    def validate(self, data):
        form = FileErrorForm(data=data)
        if not form.is_valid():
            raise serializers.ValidationError(form.errors)
        return data



class NotificationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notifications
        fields = ['id', 'user', 'title', 'description', 'created_at']

    def get_notifications(self, user):
        notifications = Notifications.objects.filter(user=user)
        serialized_notifications = self.__class__(notifications, many=True)
        return serialized_notifications.data
        


class SubscriptionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscriptions
        fields = ['id', 'user', 'full_name', 'title', 'created_at']

    def create(self, validated_data):
        user = self.context['request'].user
        subscription = Subscriptions.objects.create(user=user, **validated_data)
        return subscription

    def get_subscriptions(self, user):
        subscriptions = Subscriptions.objects.filter(user=user)
        serialized_subscriptions = self.__class__(subscriptions, many=True)
        return serialized_subscriptions.data
    
    def validate(self, data):
        form = SubscriptionsForm(data=data)
        if not form.is_valid():
            raise serializers.ValidationError(form.errors)
        return data
