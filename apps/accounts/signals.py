from django.db.models.signals import post_save, pre_save
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.sessions.models import Session

from .models import User, SecurityEvent, UserLoginHistory, UserDevice
from . import tasks


@receiver(post_save, sender=User)
def user_post_save(sender, instance, created, **kwargs):
    """Handle user post-save events"""
    if created:
        tasks.log_security_event_async(
            'USER_REGISTERED',
            instance.id,
            {'user_type': instance.user_type}
        )


@receiver(pre_save, sender=User)
def user_pre_save(sender, instance, **kwargs):
    """Track changes to user model"""
    if not instance.pk:
        return
    
    try:
        old_instance = User.objects.get(pk=instance.pk)
        
        # Check for security-relevant changes
        changes = []
        
        if old_instance.password != instance.password:
            changes.append('password_changed')
        
        if old_instance.phone_number != instance.phone_number:
            changes.append('phone_changed')
        
        if not old_instance.two_factor_enabled and instance.two_factor_enabled:
            changes.append('2fa_enabled')
        
        if old_instance.two_factor_enabled and not instance.two_factor_enabled:
            changes.append('2fa_disabled')
        
        if changes:
            # Store changes in instance for post-save
            instance._security_changes = changes
            
    except User.DoesNotExist:
        pass


@receiver(user_logged_in)
def user_logged_in_handler(sender, request, user, **kwargs):
    """Handle user login"""
    # Update last login
    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])
    
    # Get client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    
    # Log security event
    tasks.log_security_event_async(
        'LOGIN_SUCCESS',
        user.id,
        {'ip': ip, 'user_agent': user_agent}
    )
    
    # Create login history
    UserLoginHistory.objects.create(
        user=user,
        ip_address=ip,
        user_agent=user_agent,
        was_successful=True,
        device_id=request.session.session_key
    )


@receiver(user_logged_out)
def user_logged_out_handler(sender, request, user, **kwargs):
    """Handle user logout"""
    if user:
        tasks.log_security_event_async('LOGOUT', user.id)


@receiver(user_login_failed)
def user_login_failed_handler(sender, credentials, request, **kwargs):
    """Handle failed login attempts"""
    phone_number = credentials.get('username', '')
    
    # Get client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    tasks.log_security_event_async(
        'LOGIN_FAILED',
        metadata={'phone_number': phone_number, 'ip': ip}
    )