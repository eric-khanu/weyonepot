import logging
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger(__name__)

# Mock async functions - will be replaced with real Celery when installed
def async_task(func):
    """Decorator to mock async tasks when Celery not installed"""
    def wrapper(*args, **kwargs):
        try:
            # Try to execute immediately
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Task failed: {str(e)}")
            return None
    return wrapper


# Task functions
@async_task
def send_otp_sms_async(phone_number, otp_code, purpose='verification'):
    """
    Send OTP via SMS asynchronously
    """
    from .utils import send_otp_sms
    logger.info(f"Sending OTP to {phone_number} for {purpose}")
    return send_otp_sms(phone_number, otp_code, purpose)


@async_task
def send_welcome_sms_async(phone_number, first_name):
    """
    Send welcome SMS to new users
    """
    from .utils import send_otp_sms
    message = f"Welcome to DigiSusu, {first_name}! Your account has been created. Please verify your phone number to start saving."
    logger.info(f"Sending welcome SMS to {phone_number}")
    return send_otp_sms(phone_number, message, 'welcome')


@async_task
def send_login_alert_async(user_id, ip_address, user_agent):
    """
    Send login alert to user
    """
    from .models import User
    from .utils import send_otp_sms
    
    try:
        user = User.objects.get(id=user_id)
        message = f"New login to your DigiSusu account from {ip_address}. If this wasn't you, please secure your account immediately."
        logger.info(f"Sending login alert to {user.phone_number}")
        return send_otp_sms(user.phone_number, message, 'security_alert')
    except Exception as e:
        logger.error(f"Failed to send login alert: {str(e)}")
        return False


@async_task
def log_security_event_async(event_type, user_id=None, metadata=None, severity='INFO'):
    """
    Log security event asynchronously
    """
    from .models import SecurityEvent, User
    
    metadata = metadata or {}
    
    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass
    
    try:
        event = SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=metadata.get('ip'),
            user_agent=metadata.get('user_agent', ''),
            metadata=metadata,
            severity=severity,
            description=metadata.get('description', '')
        )
        logger.info(f"Security event logged: {event_type}")
        return event
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")
        return None


@async_task
def cleanup_expired_otps():
    """
    Clean up expired OTP codes
    """
    from .models import UserOTP
    expired = UserOTP.objects.filter(expires_at__lt=timezone.now())
    count = expired.count()
    expired.delete()
    logger.info(f"Cleaned up {count} expired OTPs")
    return count


@async_task
def delete_inactive_users(days=30):
    """
    Delete users who haven't verified their account after X days
    """
    from .models import User
    
    cutoff_date = timezone.now() - timedelta(days=days)
    inactive_users = User.objects.filter(
        is_active=False,
        is_verified=False,
        date_joined__lt=cutoff_date
    )
    
    count = inactive_users.count()
    inactive_users.delete()
    logger.info(f"Deleted {count} inactive unverified users older than {days} days")
    return count