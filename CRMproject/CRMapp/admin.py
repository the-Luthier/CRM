from django.contrib import admin
from django.contrib.admin.sites import NotRegistered
from .models import Profile, Device, FileError, Notifications, Subscriptions
from .utils import send_push_notifications

admin.site.register(Profile)
admin.site.register(Device)
admin.site.register(FileError)
admin.site.register(Notifications)
admin.site.register(Subscriptions)


def send_notifications(modeladmin, request, queryset):
    profile_ids = queryset.values_list('id', flat=True)
    device_tokens = Device.objects.filter(profile__in=profile_ids).values_list('device_token', flat=True)
    
    title = "Your notification title"
    message = "Your notification message"
    
    send_push_notifications(device_tokens, title, message)

send_notifications.short_description = "Send notifications to selected profiles"

class CustomProfileAdmin(admin.ModelAdmin):
    actions = [send_notifications]

# Unregister the Profile model if it's already registered
try:
    admin.site.unregister(Profile)
except NotRegistered:
    pass

# Register the Profile model with the custom admin class
admin.site.register(Profile, CustomProfileAdmin)