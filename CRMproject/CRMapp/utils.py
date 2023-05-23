from pyfcm import FCMNotification

def send_push_notifications(device_tokens, title, message):
    # Replace with your FCM server key
    server_key = "your_fcm_server_key"
    
    push_service = FCMNotification(api_key=server_key)
    
    # You can customize the notification data as needed
    data = {
        'title': title,
        'body': message,
    }
    
    result = push_service.notify_multiple_devices(registration_ids=device_tokens, data_message=data)
    
    return result