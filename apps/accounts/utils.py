import re
import secrets
import string
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
import requests
from .tasks import send_otp_sms_async
import pyotp

from .models import UserOTP, SecurityEvent

logger = logging.getLogger(__name__)


# ========== PHONE NUMBER UTILITIES ==========

def normalize_phone(phone):
    """
    Normalize phone number to standard format (0XXXXXXXXX)
    """
    if not phone:
        return phone
    
    # Remove all non-digit characters except leading +
    phone = re.sub(r'[^\d+]', '', phone)
    
    # Handle international format
    if phone.startswith('+232'):
        phone = '0' + phone[4:]
    elif phone.startswith('232'):
        phone = '0' + phone[3:]
    elif phone.startswith('+') and not phone.startswith('+232'):
        raise ValueError('Only Sierra Leone numbers (+232) are allowed')
    
    # Ensure it's 10 digits
    if len(phone) == 9 and not phone.startswith('0'):
        phone = '0' + phone
    
    return phone


def validate_sl_phone(phone):
    """
    Validate Sierra Leone phone number format
    """
    if not phone:
        return False
    
    # Remove spaces and dashes
    phone = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Sierra Leone prefixes: 76,77,78,79,30,31,32,33,34,88,99
    pattern = r'^(?:(?:\+?232)|0)?(76|77|78|79|30|31|32|33|34|88|99)[0-9]{6}$'
    return bool(re.match(pattern, phone))


def format_phone_display(phone):
    """
    Format phone number for display (e.g., 076 123 456)
    """
    if not phone:
        return phone
    
    phone = re.sub(r'[\s\-\(\)]', '', phone)
    
    if len(phone) >= 7:
        return f"{phone[:3]} {phone[3:6]} {phone[6:]}"
    
    return phone


def mask_phone(phone):
    """
    Mask phone number for display (e.g., 076*****56)
    """
    if not phone or len(phone) < 8:
        return phone
    
    phone = re.sub(r'[\s\-\(\)]', '', phone)
    return phone[:3] + '*****' + phone[-2:]


# ========== OTP UTILITIES ==========

def generate_otp(user, purpose, length=6):
    """
    Generate a secure OTP for user
    """
    # Generate cryptographically secure random digits
    otp_code = ''.join(secrets.choice('0123456789') for _ in range(length))
    
    otp = UserOTP.objects.create(
        user=user,
        otp_code=otp_code,
        purpose=purpose,
        expires_at=timezone.now() + timedelta(minutes=10)
    )
    
    return otp


def verify_otp(user, otp_code, purpose):
    """
    Verify OTP code for user
    """
    try:
        otp = UserOTP.objects.filter(
            user=user,
            purpose=purpose,
            is_used=False,
            expires_at__gt=timezone.now()
        ).latest('created_at')
        
        return otp.verify(otp_code)
        
    except UserOTP.DoesNotExist:
        return False


def send_otp_sms(phone_number, otp_code, purpose='verification', async_mode=True):
    """
    Send OTP via SMS with support for multiple SMS gateways
    If async_mode is True and in production, use Celery async task
    """
    # For development, log to console (always sync)
    if settings.DEBUG:
        print(f"\n🔐 OTP for {phone_number}: {otp_code}\n")
        return True
    
    # Use async task in production if requested
    if async_mode and not settings.DEBUG:
        try:
            send_otp_sms_async.delay(phone_number, otp_code, purpose)
            logger.info(f"Queued async SMS task for {phone_number}")
            return True
        except Exception as e:
            logger.error(f"Failed to queue async SMS: {str(e)}")
            # Fall through to sync sending
    
    # For production, try different SMS gateways (sync fallback)
    try:
        message = f"Your DigiSusu {purpose} code is: {otp_code}. Valid for 10 minutes."
        
        # Try AfricasTalking if configured
        if hasattr(settings, 'AFRICASTALKING_USERNAME') and hasattr(settings, 'AFRICASTALKING_API_KEY'):
            try:
                import africastalking
                africastalking.initialize(
                    username=settings.AFRICASTALKING_USERNAME,
                    api_key=settings.AFRICASTALKING_API_KEY
                )
                sms = africastalking.SMS
                response = sms.send(message, [phone_number])
                if response['SMSMessageData']['Recipients'][0]['status'] == 'Success':
                    logger.info(f"SMS sent via AfricasTalking to {phone_number}")
                    return True
            except ImportError:
                logger.warning("AfricasTalking package not installed. Trying alternative gateway.")
            except Exception as e:
                logger.error(f"AfricasTalking SMS failed: {str(e)}")
        
        # Try Twilio if configured
        if hasattr(settings, 'TWILIO_ACCOUNT_SID') and hasattr(settings, 'TWILIO_AUTH_TOKEN'):
            try:
                from twilio.rest import Client
                client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                message = client.messages.create(
                    body=message,
                    from_=settings.TWILIO_PHONE_NUMBER,
                    to=phone_number
                )
                if message.sid:
                    logger.info(f"SMS sent via Twilio to {phone_number}")
                    return True
            except ImportError:
                logger.warning("Twilio package not installed.")
            except Exception as e:
                logger.error(f"Twilio SMS failed: {str(e)}")
        
        # Try generic HTTP API (like Infobip, Clickatell, etc.)
        if hasattr(settings, 'SMS_API_URL'):
            try:
                payload = {
                    'to': phone_number,
                    'message': message,
                    'from': settings.SMS_SENDER_ID,
                }
                
                headers = {}
                if hasattr(settings, 'SMS_API_KEY'):
                    headers['Authorization'] = f'Bearer {settings.SMS_API_KEY}'
                
                response = requests.post(
                    settings.SMS_API_URL,
                    json=payload,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code in [200, 201, 202]:
                    logger.info(f"SMS sent via HTTP API to {phone_number}")
                    return True
            except Exception as e:
                logger.error(f"HTTP SMS API failed: {str(e)}")
        
        # Log to file as fallback
        logger.info(f"SMS to {phone_number}: {message}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send SMS to {phone_number}: {str(e)}")
        
        # Log to file in production as well
        message = f"OTP for {phone_number}: {otp_code}"
        logger.info(f"OTP (SMS failed): {message}")
        return True  # Return True to not block the flow in production

# ========== PASSWORD UTILITIES ==========

def check_password_strength(password):
    """
    Check password strength and return (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    
    # Check for common patterns
    common_patterns = ['123456', 'password', 'qwerty', 'admin', 'user', 'letmein']
    if any(pattern in password.lower() for pattern in common_patterns):
        return False, "Password contains common patterns that are easy to guess."
    
    return True, "Password is strong."


def hash_token(token):
    """
    Hash a token for storage
    """
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_compare(val1, val2):
    """
    Compare two strings in constant time to prevent timing attacks
    """
    return hmac.compare_digest(str(val1), str(val2))


# ========== SECURITY EVENT LOGGING ==========

def log_security_event(event_type, user=None, request=None, metadata=None, severity='INFO'):
    """
    Log a security event
    """
    metadata = metadata or {}
    
    # Get request info if available
    if request:
        metadata.update({
            'ip': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:255],
            'path': request.path,
            'method': request.method,
        })
    
    # Create event
    event = SecurityEvent.objects.create(
        user=user,
        event_type=event_type,
        ip_address=metadata.get('ip'),
        user_agent=metadata.get('user_agent', ''),
        metadata=metadata,
        severity=severity,
        description=metadata.get('description', '')
    )
    
    # Log to file
    log_message = f"SECURITY [{severity}]: {event_type}"
    if user:
        log_message += f" - User: {user.phone_number}"
    if metadata:
        # Remove sensitive data from logs
        safe_metadata = {k: v for k, v in metadata.items() if k not in ['password', 'token']}
        log_message += f" - {safe_metadata}"
    
    if severity == 'CRITICAL':
        logger.critical(log_message)
    elif severity == 'WARNING':
        logger.warning(log_message)
    else:
        logger.info(log_message)
    
    # Send alert for critical events
    if severity == 'CRITICAL':
        send_security_alert(event)
    
    return event


def get_client_ip(request):
    """
    Get client IP address from request
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# ========== RATE LIMITING ==========

def check_rate_limit(key, max_attempts, timeout_seconds):
    """
    Check rate limit for a key
    """
    current = cache.get(key, 0)
    
    if current >= max_attempts:
        return False
    
    cache.set(key, current + 1, timeout_seconds)
    return True


def increment_rate_limit(key, timeout_seconds):
    """
    Increment rate limit counter
    """
    current = cache.get(key, 0)
    cache.set(key, current + 1, timeout_seconds)


def get_rate_limit_remaining(key, max_attempts):
    """
    Get remaining attempts for rate limit
    """
    current = cache.get(key, 0)
    return max(0, max_attempts - current)


# ========== EMAIL UTILITIES ==========

def send_html_email(subject, template_name, context, to_emails):
    """
    Send HTML email
    """
    html_message = render_to_string(template_name, context)
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=to_emails if isinstance(to_emails, list) else [to_emails],
        html_message=html_message,
        fail_silently=False,
    )


def send_security_alert(event):
    """
    Send security alert for critical events
    """
    if not hasattr(settings, 'ADMIN_EMAILS') or not settings.ADMIN_EMAILS:
        return
    
    subject = f"[SECURITY ALERT] {event.get_event_type_display()}"
    
    context = {
        'event': event,
        'user': event.user,
        'timestamp': event.created_at,
    }
    
    send_html_email(
        subject=subject,
        template_name='emails/security_alert.html',
        context=context,
        to_emails=settings.ADMIN_EMAILS
    )


# ========== TOKEN UTILITIES ==========

def generate_secure_token(length=32):
    """
    Generate a cryptographically secure random token
    """
    return secrets.token_urlsafe(length)


def generate_numeric_code(length=6):
    """
    Generate a secure numeric code
    """
    return ''.join(secrets.choice('0123456789') for _ in range(length))


def generate_backup_codes(count=8):
    """
    Generate backup codes for 2FA
    """
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        codes.append(code)
    
    return codes


# ========== 2FA UTILITIES ==========

def generate_totp_secret():
    """
    Generate TOTP secret for authenticator apps
    """
    try:
        import pyotp
        return pyotp.random_base32()
    except ImportError:
        logger.warning("pyotp not installed. Using fallback secret generation.")
        return secrets.token_hex(16)


def get_totp_uri(secret, name, issuer="DigiSusu"):
    """
    Get TOTP URI for QR code
    """
    try:
        import pyotp
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=name,
            issuer_name=issuer
        )
    except ImportError:
        logger.warning("pyotp not installed. Cannot generate TOTP URI.")
        return f"otpauth://totp/{issuer}:{name}?secret={secret}&issuer={issuer}"


def verify_totp(secret, token):
    """
    Verify TOTP token
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    except ImportError:
        logger.warning("pyotp not installed. Cannot verify TOTP.")
        return False


# ========== SESSION UTILITIES ==========

def get_session_data(request):
    """
    Get session data for current request
    """
    return {
        'session_key': request.session.session_key,
        'user_agent': request.META.get('HTTP_USER_AGENT', '')[:255],
        'ip_address': get_client_ip(request),
        'path': request.path,
        'method': request.method,
    }


def clear_expired_sessions():
    """
    Clear expired sessions from database
    """
    from django.contrib.sessions.models import Session
    Session.objects.filter(expire_date__lt=timezone.now()).delete()


# ========== FORMATTING UTILITIES ==========

def format_currency(amount):
    """
    Format amount as Sierra Leone currency
    """
    return f"Le {amount:,.2f}"


def format_datetime(dt, format='%d %b %Y, %H:%M'):
    """
    Format datetime for display
    """
    if not dt:
        return ''
    return dt.strftime(format)


def time_ago(dt):
    """
    Return human readable time ago
    """
    if not dt:
        return ''
    
    now = timezone.now()
    diff = now - dt
    
    if diff.days > 365:
        years = diff.days // 365
        return f"{years} year{'s' if years != 1 else ''} ago"
    if diff.days > 30:
        months = diff.days // 30
        return f"{months} month{'s' if months != 1 else ''} ago"
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
    if diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    if diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    
    return "just now"