from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django.urls import reverse
from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.db import transaction
from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum
import json
import secrets
import hashlib
import re
from datetime import timedelta

from .models import User, UserOTP, UserDevice, SecurityEvent, UserLoginHistory
from .forms import (
    UserRegistrationForm, UserLoginForm, UserProfileForm,
    OTPVerificationForm, PasswordChangeForm, PhoneNumberForm,
    TwoFactorSetupForm, TwoFactorVerifyForm, Disable2FAForm,
    BackupCodeForm
)
from .decorators import (
    unauthenticated_required, verified_required,
    rate_limit, ajax_required, check_account_lockout
)
from . import tasks
from .utils import (
    generate_otp, send_otp_sms, get_client_ip,
    verify_otp, mask_phone, generate_backup_codes,
    verify_totp, format_phone_display, normalize_phone,
    validate_sl_phone
)

import logging
logger = logging.getLogger(__name__)


# ========== HELPER FUNCTIONS ==========

def track_user_device(request, user):
    """
    Track or update user device information
    """
    device_id = request.session.session_key
    
    if not device_id:
        request.session.create()
        device_id = request.session.session_key
    
    # Get or create device
    device, created = UserDevice.objects.get_or_create(
        user=user,
        device_id=device_id,
        defaults={
            'device_name': get_device_name(request),
            'device_type': 'WEB',
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:255],
            'last_used': timezone.now()
        }
    )
    
    if not created:
        device.update_usage(
            ip=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
    
    return device


def get_device_name(request):
    """
    Get a readable device name from user agent
    """
    user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
    
    if 'mobile' in user_agent:
        return 'Mobile Device'
    elif 'tablet' in user_agent:
        return 'Tablet'
    elif 'windows' in user_agent:
        return 'Windows PC'
    elif 'mac' in user_agent:
        return 'Mac'
    elif 'linux' in user_agent:
        return 'Linux PC'
    else:
        return 'Web Browser'


def perform_login(request, user, remember_me=False):
    """
    Helper function to perform actual login after all checks pass
    """
    # Log the user in
    login(request, user)
    
    # Set session expiry based on remember me
    if not remember_me:
        request.session.set_expiry(0)  # Browser session
    
    # Update user stats
    user.last_login = timezone.now()
    user.failed_login_attempts = 0
    user.save(update_fields=['last_login', 'failed_login_attempts'])
    
    # Track device
    device = track_user_device(request, user)
    
    # Create login history
    UserLoginHistory.objects.create(
        user=user,
        login_time=timezone.now(),
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:255],
        was_successful=True,
        device_id=request.session.session_key,
        device_type='WEB'
    )
    
    # Send login alert asynchronously (if not from trusted device)
    if not device or not device.is_trusted_valid():
        tasks.send_login_alert_async(
            user.id,
            get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', '')[:255]
        )
    
    # Log security event
    tasks.log_security_event_async(
        'LOGIN_SUCCESS',
        user.id,
        {
            'ip': get_client_ip(request),
            'device': device.device_name if device else 'Unknown',
            'trusted': device.is_trusted_valid() if device else False
        },
        'INFO'
    )
    
    messages.success(request, f'Welcome back, {user.get_short_name()}!')
    
    # Redirect to next page or dashboard
    next_url = request.GET.get('next')
    if next_url and next_url != '/logout/':
        return redirect(next_url)
    return redirect('accounts:dashboard')


# ========== AUTHENTICATION VIEWS ==========

@unauthenticated_required
@never_cache
@rate_limit(key_func=lambda r: get_client_ip(r), max_attempts=5, timeout=3600)
def register_view(request):
    """
    User registration view with comprehensive validation
    """
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Create user but keep inactive until OTP verification
                    user = form.save(commit=False)
                    user.is_active = False  # Deactivate until OTP verified
                    
                    # Set registration IP
                    user.security_profile = user.security_profile or {}
                    user.security_profile['registration_ip'] = get_client_ip(request)
                    user.security_profile['registration_user_agent'] = request.META.get('HTTP_USER_AGENT', '')[:255]
                    
                    user.save()
                    
                    # Generate and send OTP
                    otp = generate_otp(user, 'REGISTER')
                    
                    # Send OTP
                    if not settings.DEBUG:
                        tasks.send_otp_sms_async(
                            user.phone_number, 
                            otp.otp_code, 
                            'registration'
                        )
                    else:
                        send_otp_sms(user.phone_number, otp.otp_code, 'registration')
                    
                    # Store verification data in session
                    request.session['verification_phone'] = user.phone_number
                    request.session['verification_purpose'] = 'REGISTER'
                    request.session['verification_expiry'] = (
                        timezone.now() + timedelta(minutes=15)
                    ).isoformat()
                    
                    # Log security event
                    tasks.log_security_event_async(
                        'USER_REGISTERED',
                        user.id,
                        {'phone': mask_phone(user.phone_number)},
                        'INFO'
                    )
                    
                    messages.success(
                        request, 
                        'Registration successful! Please verify your phone number with the OTP sent to you.'
                    )
                    return redirect('accounts:verify-otp')
                    
            except Exception as e:
                logger.error(f"Registration error: {str(e)}")
                messages.error(request, 'Registration failed. Please try again.')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserRegistrationForm()
    
    return render(request, 'accounts/register.html', {
        'form': form,
        'title': 'Create Account',
        'phone_prefix': '+232',
        'debug': settings.DEBUG
    })


@unauthenticated_required
@never_cache
@rate_limit(key_func=lambda r: get_client_ip(r), max_attempts=10, timeout=1800)
def login_view(request):
    """
    User login view with support for 2FA and device tracking
    """
    # Check for existing 2FA session
    if request.session.get('2fa_user_id'):
        return redirect('accounts:verify-2fa')
    
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            phone_number = form.cleaned_data.get('phone_number')
            password = form.cleaned_data.get('password')
            remember_me = form.cleaned_data.get('remember_me', False)
            
            # Authenticate user
            user = authenticate(request, username=phone_number, password=password)
            
            if user is not None:
                # Check account status
                if not user.is_active:
                    messages.error(
                        request, 
                        'This account is inactive. Please verify your phone number or contact support.'
                    )
                    return redirect('accounts:verify-otp')
                
                # Check if account is locked
                if user.is_locked():
                    lockout_time = user.locked_until.strftime('%H:%M')
                    messages.error(
                        request, 
                        f'Account locked until {lockout_time}. Too many failed attempts.'
                    )
                    return render(request, 'accounts/login.html', {'form': form})
                
                # Check if 2FA is enabled
                if user.requires_2fa():
                    # Generate and send 2FA OTP
                    otp = generate_otp(user, 'TWO_FACTOR')
                    
                    # Send OTP
                    if not settings.DEBUG:
                        tasks.send_otp_sms_async(
                            user.phone_number, 
                            otp.otp_code, 
                            '2fa'
                        )
                    else:
                        send_otp_sms(user.phone_number, otp.otp_code, '2fa')
                    
                    # Store user ID in session for 2FA verification
                    request.session['2fa_user_id'] = user.id
                    request.session['2fa_remember'] = remember_me
                    request.session['2fa_expiry'] = (
                        timezone.now() + timedelta(minutes=5)
                    ).isoformat()
                    
                    messages.info(
                        request, 
                        'Please enter the 2FA code sent to your phone.'
                    )
                    return redirect('accounts:verify-2fa')
                
                # Regular login
                return perform_login(request, user, remember_me)
            else:
                messages.error(request, 'Invalid phone number or password.')
        else:
            for error in form.non_field_errors():
                messages.error(request, error)
    else:
        form = UserLoginForm()
    
    return render(request, 'accounts/login.html', {
        'form': form,
        'title': 'Sign In',
        'next': request.GET.get('next', ''),
        'phone_prefix': '+232'
    })


@never_cache
def verify_otp_view(request):
    """
    OTP verification view for registration and password reset
    """
    # Check if we have verification data in session
    phone_number = request.session.get('verification_phone')
    purpose = request.session.get('verification_purpose', 'REGISTER')
    expiry = request.session.get('verification_expiry')
    
    # Check expiry
    if expiry:
        try:
            if timezone.now() > timezone.datetime.fromisoformat(expiry):
                # Clear expired session
                request.session.pop('verification_phone', None)
                request.session.pop('verification_purpose', None)
                request.session.pop('verification_expiry', None)
                messages.error(request, 'Verification session expired. Please start over.')
                return redirect('accounts:register' if purpose == 'REGISTER' else 'accounts:request-otp')
        except:
            pass
    
    if not phone_number:
        messages.error(request, 'No verification in progress. Please register or request OTP again.')
        return redirect('accounts:register')
    
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            
            try:
                user = User.objects.get(phone_number=phone_number)
                
                # Verify OTP
                if verify_otp(user, otp_code, purpose):
                    
                    if purpose == 'REGISTER':
                        # Activate user
                        with transaction.atomic():
                            user.is_active = True
                            user.is_verified = True
                            user.verified_at = timezone.now()
                            user.save(update_fields=['is_active', 'is_verified', 'verified_at'])
                            
                            # Log user in
                            login(request, user)
                            
                            # Send welcome SMS
                            if not settings.DEBUG:
                                tasks.send_welcome_sms_async(
                                    user.phone_number,
                                    user.first_name or 'User'
                                )
                            
                            # Log security event
                            tasks.log_security_event_async(
                                'USER_VERIFIED',
                                user.id,
                                {'method': 'otp'},
                                'INFO'
                            )
                        
                        # Clear session
                        request.session.pop('verification_phone', None)
                        request.session.pop('verification_purpose', None)
                        request.session.pop('verification_expiry', None)
                        
                        messages.success(
                            request, 
                            'Phone number verified successfully! Welcome to DigiSusu.'
                        )
                        return redirect('accounts:dashboard')
                        
                    elif purpose == 'RESET_PASSWORD':
                        # Redirect to password reset
                        request.session['reset_verified'] = True
                        request.session['reset_phone'] = phone_number
                        request.session['reset_expiry'] = (
                            timezone.now() + timedelta(minutes=15)
                        ).isoformat()
                        return redirect('accounts:password-reset-confirm')
                    
                else:
                    messages.error(request, 'Invalid or expired OTP code.')
                    
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
    else:
        form = OTPVerificationForm()
    
    return render(request, 'accounts/verify_otp.html', {
        'form': form,
        'phone_number': mask_phone(phone_number),
        'phone_display': format_phone_display(phone_number),
        'purpose': purpose.lower(),
        'title': 'Verify OTP',
        'expiry': expiry
    })


@never_cache
def verify_2fa_view(request):
    """
    2FA verification view for login
    """
    # Check for 2FA session
    user_id = request.session.get('2fa_user_id')
    expiry = request.session.get('2fa_expiry')
    
    # Check expiry
    if expiry:
        try:
            if timezone.now() > timezone.datetime.fromisoformat(expiry):
                request.session.pop('2fa_user_id', None)
                request.session.pop('2fa_remember', None)
                request.session.pop('2fa_expiry', None)
                messages.error(request, '2FA session expired. Please login again.')
                return redirect('accounts:login')
        except:
            pass
    
    if not user_id:
        messages.error(request, 'No 2FA session found. Please login again.')
        return redirect('accounts:login')
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('accounts:login')
    
    if request.method == 'POST':
        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            trust_device = form.cleaned_data.get('trust_device', False)
            
            verified = False
            
            # Check if it's a backup code
            if len(otp_code) == 8 and otp_code.isalnum():
                if user.verify_backup_code(otp_code):
                    verified = True
                    tasks.log_security_event_async(
                        'TWO_FACTOR_RECOVERY',
                        user.id,
                        {'method': 'backup_code'},
                        'WARNING'
                    )
            else:
                # Verify based on 2FA method
                if user.two_factor_method == 'SMS':
                    verified = verify_otp(user, otp_code, 'TWO_FACTOR')
                elif user.two_factor_method == 'TOTP':
                    verified = verify_totp(user.totp_secret, otp_code)
            
            if verified:
                # Clear 2FA session
                request.session.pop('2fa_user_id', None)
                request.session.pop('2fa_expiry', None)
                
                # Trust device if requested
                if trust_device:
                    device = UserDevice.objects.filter(
                        user=user,
                        device_id=request.session.session_key
                    ).first()
                    if device:
                        device.is_trusted = True
                        device.trusted_until = timezone.now() + timedelta(days=30)
                        device.save()
                
                # Complete login
                remember = request.session.get('2fa_remember', False)
                request.session.pop('2fa_remember', None)
                
                return perform_login(request, user, remember)
            else:
                messages.error(request, 'Invalid verification code.')
    else:
        form = TwoFactorVerifyForm()
    
    # Check if user has backup codes
    has_backup_codes = len(user.backup_codes) > 0
    
    return render(request, 'accounts/verify_2fa.html', {
        'form': form,
        'phone_number': mask_phone(user.phone_number),
        'phone_display': format_phone_display(user.phone_number),
        'method': dict(User._meta.get_field('two_factor_method').choices).get(user.two_factor_method, 'SMS'),
        'has_backup_codes': has_backup_codes,
        'title': 'Two-Factor Authentication'
    })


@login_required
def logout_view(request):
    """
    Logout view with session cleanup
    """
    user = request.user
    
    # Log security event
    tasks.log_security_event_async(
        'LOGOUT',
        user.id,
        {
            'ip': get_client_ip(request),
            'session_key': request.session.session_key
        },
        'INFO'
    )
    
    # Clear session
    request.session.flush()
    
    # Logout
    logout(request)
    
    messages.success(request, 'You have been logged out successfully.')
    return redirect('accounts:login')


# ========== DASHBOARD & PROFILE VIEWS ==========

@login_required
@verified_required
@check_account_lockout
def dashboard_view(request):
    """
    User dashboard with overview
    """
    user = request.user
    
    # Get recent security events
    recent_events = SecurityEvent.objects.filter(
        user=user
    ).order_by('-created_at')[:5]
    
    # Get trusted devices count
    devices_count = UserDevice.objects.filter(
        user=user,
        is_active=True
    ).count()
    
    # Calculate account age
    account_age_days = (timezone.now() - user.date_joined).days
    
    context = {
        'user': user,
        'recent_events': recent_events,
        'devices_count': devices_count,
        'account_age_days': account_age_days,
        'title': 'Dashboard'
    }
    return render(request, 'accounts/dashboard.html', context)


@login_required
@verified_required
def profile_view(request):
    """
    User profile view and edit
    """
    user = request.user
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            with transaction.atomic():
                form.save()
                
                # Log profile update
                tasks.log_security_event_async(
                    'PROFILE_UPDATED',
                    user.id,
                    {'fields': list(form.changed_data)},
                    'INFO'
                )
            
            messages.success(request, 'Profile updated successfully!')
            return redirect('accounts:profile')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserProfileForm(instance=user)
    
    context = {
        'form': form,
        'user': user,
        'title': 'My Profile'
    }
    return render(request, 'accounts/profile.html', context)


@login_required
@verified_required
def change_password_view(request):
    """
    Change password view with security checks
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            with transaction.atomic():
                form.save()
                
                # Update last password change
                request.user.last_password_change = timezone.now()
                request.user.save(update_fields=['last_password_change'])
                
                # Log security event
                tasks.log_security_event_async(
                    'PASSWORD_CHANGED',
                    request.user.id,
                    {'ip': get_client_ip(request)},
                    'INFO'
                )
            
            messages.success(
                request, 
                'Password changed successfully! Please login with your new password.'
            )
            
            # Logout user to force login with new password
            logout(request)
            return redirect('accounts:login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'accounts/change_password.html', {
        'form': form,
        'title': 'Change Password'
    })


# ========== PASSWORD RESET VIEWS ==========

@unauthenticated_required
@rate_limit(key_func=lambda r: get_client_ip(r), max_attempts=3, timeout=3600)
def request_otp_view(request):
    """
    Request OTP for password reset
    """
    if request.method == 'POST':
        form = PhoneNumberForm(request.POST)
        if form.is_valid():
            phone_number = form.cleaned_data.get('phone_number')
            
            try:
                user = User.objects.get(phone_number=phone_number)
                
                # Check if account is locked
                if user.is_locked():
                    messages.error(
                        request,
                        'This account is locked. Please try again later.'
                    )
                    return render(request, 'accounts/request_otp.html', {'form': form})
                
                # Generate OTP
                otp = generate_otp(user, 'RESET_PASSWORD')
                
                # Send OTP
                if not settings.DEBUG:
                    tasks.send_otp_sms_async(
                        user.phone_number,
                        otp.otp_code,
                        'password reset'
                    )
                else:
                    send_otp_sms(user.phone_number, otp.otp_code, 'password reset')
                
                # Store in session
                request.session['verification_phone'] = phone_number
                request.session['verification_purpose'] = 'RESET_PASSWORD'
                request.session['verification_expiry'] = (
                    timezone.now() + timedelta(minutes=15)
                ).isoformat()
                
                # Log event
                tasks.log_security_event_async(
                    'PASSWORD_RESET_REQUEST',
                    user.id,
                    {'ip': get_client_ip(request)},
                    'INFO'
                )
                
                messages.success(request, 'OTP sent to your phone number.')
                return redirect('accounts:verify-otp')
                
            except User.DoesNotExist:
                # Don't reveal if user exists - show generic message
                messages.success(
                    request,
                    'If an account exists with this number, an OTP will be sent.'
                )
                return redirect('accounts:request-otp')
    else:
        form = PhoneNumberForm()
    
    return render(request, 'accounts/request_otp.html', {
        'form': form,
        'title': 'Reset Password',
        'phone_prefix': '+232'
    })


@unauthenticated_required
def password_reset_confirm_view(request):
    """
    Password reset confirmation after OTP verification
    """
    # Check verification
    if not request.session.get('reset_verified'):
        messages.error(request, 'Please verify your identity first.')
        return redirect('accounts:request-otp')
    
    # Check expiry
    expiry = request.session.get('reset_expiry')
    if expiry:
        try:
            if timezone.now() > timezone.datetime.fromisoformat(expiry):
                request.session.pop('reset_verified', None)
                request.session.pop('reset_phone', None)
                request.session.pop('reset_expiry', None)
                messages.error(request, 'Reset session expired. Please start over.')
                return redirect('accounts:request-otp')
        except:
            pass
    
    phone_number = request.session.get('reset_phone')
    
    if request.method == 'POST':
        password = request.POST.get('new_password')
        password2 = request.POST.get('confirm_password')
        
        if password != password2:
            messages.error(request, 'Passwords do not match.')
        elif len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters.')
        elif not re.search(r'[A-Z]', password):
            messages.error(request, 'Password must contain at least one uppercase letter.')
        elif not re.search(r'[a-z]', password):
            messages.error(request, 'Password must contain at least one lowercase letter.')
        elif not re.search(r'[0-9]', password):
            messages.error(request, 'Password must contain at least one number.')
        else:
            try:
                with transaction.atomic():
                    user = User.objects.get(phone_number=phone_number)
                    
                    # Check if password was used before
                    if user.is_password_reused(password):
                        messages.error(
                            request,
                            'You have used this password recently. Please choose a different password.'
                        )
                        return render(request, 'accounts/password_reset_confirm.html', {
                            'phone_number': mask_phone(phone_number)
                        })
                    
                    user.set_password(password)
                    user.last_password_change = timezone.now()
                    user.save(update_fields=['password', 'last_password_change'])
                    
                    # Log event
                    tasks.log_security_event_async(
                        'PASSWORD_RESET_COMPLETE',
                        user.id,
                        {'ip': get_client_ip(request)},
                        'INFO'
                    )
                    
                    # Clear session
                    request.session.pop('verification_phone', None)
                    request.session.pop('verification_purpose', None)
                    request.session.pop('reset_verified', None)
                    request.session.pop('reset_phone', None)
                    request.session.pop('reset_expiry', None)
                    
                    messages.success(
                        request,
                        'Password reset successfully! Please login with your new password.'
                    )
                    return redirect('accounts:login')
                    
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
    
    return render(request, 'accounts/password_reset_confirm.html', {
        'phone_number': mask_phone(phone_number),
        'phone_display': format_phone_display(phone_number) if phone_number else '',
        'title': 'Set New Password'
    })


# ========== TWO-FACTOR AUTHENTICATION VIEWS ==========

@login_required
@verified_required
def setup_2fa_view(request):
    """
    Setup two-factor authentication
    """
    user = request.user
    
    # If 2FA already enabled, redirect to security
    if user.two_factor_enabled:
        messages.info(request, 'Two-factor authentication is already enabled.')
        return redirect('accounts:security')
    
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            method = form.cleaned_data.get('method')
            otp_code = form.cleaned_data.get('otp_code')
            
            # Verify OTP
            verified = False
            
            if method == 'SMS':
                verified = verify_otp(user, otp_code, 'TWO_FACTOR_SETUP')
            elif method == 'TOTP':
                verified = verify_totp(user.totp_secret, otp_code)
            
            if verified:
                with transaction.atomic():
                    # Enable 2FA
                    user.two_factor_enabled = True
                    user.two_factor_method = method
                    
                    # Generate backup codes
                    backup_codes = generate_backup_codes(8)
                    user.backup_codes = [
                        hashlib.sha256(code.encode()).hexdigest() 
                        for code in backup_codes
                    ]
                    
                    user.save(update_fields=['two_factor_enabled', 'two_factor_method', 'backup_codes'])
                    
                    # Store plain backup codes in session for one-time display
                    request.session['new_backup_codes'] = backup_codes
                    
                    # Log event
                    tasks.log_security_event_async(
                        'TWO_FACTOR_ENABLED',
                        user.id,
                        {'method': method},
                        'INFO'
                    )
                
                messages.success(
                    request,
                    'Two-factor authentication enabled successfully! '
                    'Please save your backup codes.'
                )
                return redirect('accounts:generate-backup-codes')
            else:
                messages.error(request, 'Invalid verification code.')
    else:
        # Generate and send setup OTP
        if not user.two_factor_enabled:
            otp = generate_otp(user, 'TWO_FACTOR_SETUP')
            
            if not settings.DEBUG:
                tasks.send_otp_sms_async(
                    user.phone_number,
                    otp.otp_code,
                    '2FA setup'
                )
            else:
                send_otp_sms(user.phone_number, otp.otp_code, '2FA setup')
        
        form = TwoFactorSetupForm()
    
    # Generate TOTP URI for QR code if needed
    totp_uri = None
    if not user.totp_secret:
        import pyotp
        user.totp_secret = pyotp.random_base32()
        user.save(update_fields=['totp_secret'])
    
    try:
        import pyotp
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
            name=user.phone_number,
            issuer_name="DigiSusu"
        )
    except ImportError:
        totp_uri = f"otpauth://totp/DigiSusu:{user.phone_number}?secret={user.totp_secret}&issuer=DigiSusu"
    
    context = {
        'form': form,
        'phone_number': mask_phone(user.phone_number),
        'phone_display': format_phone_display(user.phone_number),
        'totp_uri': totp_uri,
        'totp_secret': user.totp_secret,
        'title': 'Setup Two-Factor Authentication'
    }
    return render(request, 'accounts/setup_2fa.html', context)


@login_required
def disable_2fa_view(request):
    """
    Disable two-factor authentication with confirmation
    """
    user = request.user
    
    if not user.two_factor_enabled:
        messages.info(request, 'Two-factor authentication is not enabled.')
        return redirect('accounts:security')
    
    if request.method == 'POST':
        form = Disable2FAForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            confirm = form.cleaned_data.get('confirm')
            
            if not confirm:
                messages.error(
                    request,
                    'You must confirm that you understand the security implications.'
                )
                return render(request, 'accounts/disable_2fa.html', {'form': form})
            
            # Verify OTP
            verified = False
            if user.two_factor_method == 'SMS':
                verified = verify_otp(user, otp_code, 'TWO_FACTOR_DISABLE')
            elif user.two_factor_method == 'TOTP':
                verified = verify_totp(user.totp_secret, otp_code)
            
            if verified:
                with transaction.atomic():
                    # Disable 2FA
                    user.two_factor_enabled = False
                    user.two_factor_method = 'SMS'
                    user.backup_codes = []
                    user.save(update_fields=['two_factor_enabled', 'two_factor_method', 'backup_codes'])
                    
                    # Log event
                    tasks.log_security_event_async(
                        'TWO_FACTOR_DISABLED',
                        user.id,
                        {'ip': get_client_ip(request)},
                        'WARNING'
                    )
                
                messages.success(request, 'Two-factor authentication disabled.')
                return redirect('accounts:security')
            else:
                messages.error(request, 'Invalid verification code.')
    else:
        # Generate disable OTP
        otp = generate_otp(user, 'TWO_FACTOR_DISABLE')
        
        if not settings.DEBUG:
            tasks.send_otp_sms_async(
                user.phone_number,
                otp.otp_code,
                '2FA disable'
            )
        else:
            send_otp_sms(user.phone_number, otp.otp_code, '2FA disable')
        
        form = Disable2FAForm()
    
    return render(request, 'accounts/disable_2fa.html', {
        'form': form,
        'phone_number': mask_phone(user.phone_number),
        'phone_display': format_phone_display(user.phone_number),
        'title': 'Disable Two-Factor Authentication'
    })


@login_required
def two_factor_recovery_view(request):
    """
    Use backup codes for 2FA recovery
    """
    user = request.user
    
    if request.method == 'POST':
        form = BackupCodeForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('backup_code')
            
            if user.verify_backup_code(code):
                # Mark session as 2FA verified
                request.session['2fa_verified'] = True
                
                # Log event
                tasks.log_security_event_async(
                    'TWO_FACTOR_RECOVERY',
                    user.id,
                    {'method': 'backup_code'},
                    'WARNING'
                )
                
                messages.success(
                    request,
                    'Backup code accepted. Please set up a new 2FA method.'
                )
                return redirect('accounts:setup-2fa')
            else:
                messages.error(request, 'Invalid backup code.')
    else:
        form = BackupCodeForm()
    
    # Get remaining codes count
    remaining_codes = len(user.backup_codes)
    
    return render(request, 'accounts/two_factor_recovery.html', {
        'form': form,
        'remaining_codes': remaining_codes,
        'title': '2FA Recovery'
    })


@login_required
def generate_backup_codes_view(request):
    """
    Generate and display new backup codes
    """
    user = request.user
    
    # Check if we have new codes from 2FA setup
    new_codes = request.session.pop('new_backup_codes', None)
    
    if request.method == 'POST':
        # Generate new codes
        backup_codes = generate_backup_codes(8)
        
        with transaction.atomic():
            # Store hashed codes
            user.backup_codes = [
                hashlib.sha256(code.encode()).hexdigest()
                for code in backup_codes
            ]
            user.save(update_fields=['backup_codes'])
            
            # Store plain codes in session for display
            request.session['new_backup_codes'] = backup_codes
            
            # Log event
            tasks.log_security_event_async(
                'BACKUP_CODES_GENERATED',
                user.id,
                {},
                'INFO'
            )
        
        messages.success(request, 'New backup codes generated.')
        return redirect('accounts:generate-backup-codes')
    
    context = {
        'backup_codes': new_codes,
        'has_codes': bool(new_codes),
        'title': 'Backup Codes'
    }
    return render(request, 'accounts/generate_backup_codes.html', context)


# ========== SECURITY & DEVICE VIEWS ==========

@login_required
@verified_required
def security_view(request):
    """
    Security settings overview
    """
    user = request.user
    
    # Get recent security events
    recent_events = SecurityEvent.objects.filter(
        user=user
    ).order_by('-created_at')[:10]
    
    # Get active devices
    devices = UserDevice.objects.filter(
        user=user,
        is_active=True
    ).order_by('-last_used')
    
    # Get login history
    login_history = UserLoginHistory.objects.filter(
        user=user
    ).order_by('-login_time')[:5]
    
    context = {
        'user': user,
        'recent_events': recent_events,
        'devices': devices,
        'login_history': login_history,
        'backup_codes_count': len(user.backup_codes),
        'title': 'Security Settings'
    }
    return render(request, 'accounts/security.html', context)


@login_required
def trusted_devices_view(request):
    """
    Manage trusted devices
    """
    user = request.user
    devices = UserDevice.objects.filter(user=user).order_by('-last_used')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        device_id = request.POST.get('device_id')
        
        try:
            device = UserDevice.objects.get(id=device_id, user=user)
            
            if action == 'remove':
                device.delete()
                messages.success(request, 'Device removed successfully.')
                
            elif action == 'trust':
                device.is_trusted = True
                device.trusted_until = timezone.now() + timedelta(days=30)
                device.save()
                messages.success(request, 'Device trusted successfully.')
                
            elif action == 'untrust':
                device.is_trusted = False
                device.trusted_until = None
                device.save()
                messages.success(request, 'Device untrusted successfully.')
                
        except UserDevice.DoesNotExist:
            messages.error(request, 'Device not found.')
        
        return redirect('accounts:trusted-devices')
    
    # Get current session device
    current_device = devices.filter(device_id=request.session.session_key).first()
    
    context = {
        'devices': devices,
        'current_device': current_device,
        'title': 'Trusted Devices'
    }
    return render(request, 'accounts/trusted_devices.html', context)


@login_required
@require_http_methods(['POST'])
def trust_all_devices_view(request):
    """
    Trust all current devices
    """
    user = request.user
    
    devices = UserDevice.objects.filter(user=user, is_active=True)
    count = devices.update(
        is_trusted=True,
        trusted_until=timezone.now() + timedelta(days=30)
    )
    
    messages.success(request, f'{count} devices trusted successfully.')
    return redirect('accounts:trusted-devices')


@login_required
def revoke_device_view(request, device_id):
    """
    Revoke a specific device
    """
    user = request.user
    
    try:
        device = UserDevice.objects.get(id=device_id, user=user)
        
        # Don't allow revoking current device
        if device.device_id == request.session.session_key:
            messages.error(request, 'Cannot revoke current device.')
        else:
            device.is_active = False
            device.save()
            messages.success(request, 'Device revoked successfully.')
            
    except UserDevice.DoesNotExist:
        messages.error(request, 'Device not found.')
    
    return redirect('accounts:trusted-devices')


@login_required
def activity_log_view(request):
    """
    View security activity log
    """
    user = request.user
    
    # Get events with pagination
    events = SecurityEvent.objects.filter(
        user=user
    ).order_by('-created_at')
    
    paginator = Paginator(events, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'title': 'Activity Log'
    }
    return render(request, 'accounts/activity_log.html', context)


# ========== ACCOUNT MANAGEMENT VIEWS ==========

@login_required
@require_http_methods(['POST'])
def delete_account_view(request):
    """
    Permanently delete user account
    """
    user = request.user
    
    # Verify password
    password = request.POST.get('password')
    if not user.check_password(password):
        messages.error(request, 'Invalid password.')
        return redirect('accounts:security')
    
    # Log event before deletion
    tasks.log_security_event_async(
        'ACCOUNT_DELETED',
        user.id,
        {'ip': get_client_ip(request)},
        'CRITICAL'
    )
    
    # Delete user
    user.delete()
    
    # Logout
    logout(request)
    
    messages.success(request, 'Your account has been permanently deleted.')
    return redirect('accounts:register')


@login_required
@require_http_methods(['POST'])
def deactivate_account_view(request):
    """
    Temporarily deactivate account
    """
    user = request.user
    
    # Verify password
    password = request.POST.get('password')
    if not user.check_password(password):
        messages.error(request, 'Invalid password.')
        return redirect('accounts:security')
    
    with transaction.atomic():
        user.is_active = False
        user.save(update_fields=['is_active'])
        
        # Log event
        tasks.log_security_event_async(
            'ACCOUNT_DEACTIVATED',
            user.id,
            {'ip': get_client_ip(request)},
            'WARNING'
        )
    
    # Logout
    logout(request)
    
    messages.success(
        request,
        'Your account has been deactivated. You can reactivate by logging in again.'
    )
    return redirect('accounts:login')


# ========== AJAX API VIEWS ==========

@ajax_required
def check_username_api(request):
    """
    Check if username (phone) is available (AJAX)
    """
    phone = request.GET.get('phone', '')
    
    if not phone:
        return JsonResponse({'available': False, 'error': 'Phone number required'})
    
    phone = normalize_phone(phone)
    
    exists = User.objects.filter(phone_number=phone).exists()
    
    return JsonResponse({
        'available': not exists,
        'message': 'Phone number is available' if not exists else 'Phone number already registered'
    })


@ajax_required
def check_email_api(request):
    """
    Check if email is available (AJAX)
    """
    email = request.GET.get('email', '').lower().strip()
    
    if not email:
        return JsonResponse({'available': False, 'error': 'Email required'})
    
    exists = User.objects.filter(email=email).exists()
    
    return JsonResponse({
        'available': not exists,
        'message': 'Email is available' if not exists else 'Email already registered'
    })


@ajax_required
@login_required
def update_profile_api(request):
    """
    Update profile via AJAX
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
    except:
        data = request.POST
    
    user = request.user
    
    # Update allowed fields
    allowed_fields = ['first_name', 'last_name', 'email', 'occupation', 'city']
    updated_fields = []
    
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
            updated_fields.append(field)
    
    if updated_fields:
        user.save(update_fields=updated_fields)
        
        # Log profile update
        tasks.log_security_event_async(
            'PROFILE_UPDATED',
            user.id,
            {'fields': updated_fields},
            'INFO'
        )
    
    return JsonResponse({
        'success': True,
        'message': 'Profile updated successfully',
        'user': {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'full_name': user.get_full_name()
        }
    })


@ajax_required
@require_http_methods(['POST'])
def resend_otp_view(request):
    """
    Resend OTP (AJAX endpoint)
    """
    phone = request.POST.get('phone_number')
    purpose = request.POST.get('purpose', 'REGISTER')
    
    if not phone:
        return JsonResponse({
            'success': False,
            'message': 'Phone number required'
        }, status=400)
    
    try:
        phone = normalize_phone(phone)
        user = User.objects.get(phone_number=phone)
        
        # Rate limiting
        cache_key = f"resend_otp_{phone}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 3:
            return JsonResponse({
                'success': False,
                'message': 'Too many OTP requests. Please try again later.'
            }, status=429)
        
        # Generate new OTP
        otp = generate_otp(user, purpose)
        
        # Send OTP
        if not settings.DEBUG:
            tasks.send_otp_sms_async(
                user.phone_number,
                otp.otp_code,
                purpose.lower()
            )
        else:
            send_otp_sms(user.phone_number, otp.otp_code, purpose.lower())
        
        # Increment attempts
        cache.set(cache_key, attempts + 1, 3600)
        
        return JsonResponse({
            'success': True,
            'message': 'OTP resent successfully.'
        })
        
    except User.DoesNotExist:
        # Don't reveal if user exists
        return JsonResponse({
            'success': True,
            'message': 'If an account exists, an OTP will be sent.'
        })


@ajax_required
@require_http_methods(['POST'])
def resend_2fa_view(request):
    """
    Resend 2FA code (AJAX endpoint)
    """
    user_id = request.session.get('2fa_user_id')
    
    if not user_id:
        return JsonResponse({
            'success': False,
            'message': 'No 2FA session found'
        }, status=400)
    
    try:
        user = User.objects.get(id=user_id)
        
        # Rate limiting
        cache_key = f"resend_2fa_{user_id}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 3:
            return JsonResponse({
                'success': False,
                'message': 'Too many 2FA requests. Please try again later.'
            }, status=429)
        
        # Generate new OTP
        otp = generate_otp(user, 'TWO_FACTOR')
        
        # Send OTP
        if not settings.DEBUG:
            tasks.send_otp_sms_async(
                user.phone_number,
                otp.otp_code,
                '2fa'
            )
        else:
            send_otp_sms(user.phone_number, otp.otp_code, '2fa')
        
        # Increment attempts
        cache.set(cache_key, attempts + 1, 300)  # 5 minute window
        
        return JsonResponse({
            'success': True,
            'message': '2FA code resent successfully.'
        })
        
    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'User not found'
        }, status=404)


@ajax_required
@require_http_methods(['POST'])
@login_required
def resend_2fa_setup_view(request):
    """
    Resend 2FA setup code (AJAX endpoint)
    """
    user = request.user
    
    # Rate limiting
    cache_key = f"resend_2fa_setup_{user.id}"
    attempts = cache.get(cache_key, 0)
    
    if attempts >= 3:
        return JsonResponse({
            'success': False,
            'message': 'Too many requests. Please try again later.'
        }, status=429)
    
    # Generate new OTP
    otp = generate_otp(user, 'TWO_FACTOR_SETUP')
    
    # Send OTP
    if not settings.DEBUG:
        tasks.send_otp_sms_async(
            user.phone_number,
            otp.otp_code,
            '2FA setup'
        )
    else:
        send_otp_sms(user.phone_number, otp.otp_code, '2FA setup')
    
    # Increment attempts
    cache.set(cache_key, attempts + 1, 300)
    
    return JsonResponse({
        'success': True,
        'message': '2FA setup code resent successfully.'
    })