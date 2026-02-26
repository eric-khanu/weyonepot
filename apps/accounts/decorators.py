from django.shortcuts import redirect
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from functools import wraps
from .utils import get_client_ip, check_rate_limit


def unauthenticated_required(view_func):
    """
    Decorator to prevent authenticated users from accessing login/register pages
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            messages.info(request, 'You are already logged in.')
            return redirect('accounts:dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper


def verified_required(view_func):
    """
    Decorator to ensure user's phone is verified
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        
        if not request.user.is_verified:
            messages.warning(
                request,
                'Please verify your phone number to access this page.'
            )
            return redirect('accounts:verify-otp')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def two_factor_required(view_func):
    """
    Decorator to ensure 2FA is enabled for certain views
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        
        if request.user.user_type == 'ADMIN' and not request.user.two_factor_enabled:
            messages.error(
                request,
                'Administrators must enable two-factor authentication.'
            )
            return redirect('accounts:setup-2fa')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def active_required(view_func):
    """
    Decorator to ensure user account is active
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        
        if not request.user.is_active:
            messages.error(
                request,
                'Your account has been deactivated. Please contact support.'
            )
            return redirect('accounts:login')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def rate_limit(key_func=None, max_attempts=5, timeout=300):
    """
    Rate limiting decorator
    
    Usage:
        @rate_limit(key_func=lambda r: r.META.get('REMOTE_ADDR'), max_attempts=3)
        def my_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Get rate limit key
            if key_func:
                key = f"rate_limit:{key_func(request)}"
            else:
                # Default: use IP address
                key = f"rate_limit:{get_client_ip(request)}"
            
            # Check rate limit
            if not check_rate_limit(key, max_attempts, timeout):
                messages.error(
                    request,
                    f"Too many attempts. Please try again in {timeout // 60} minutes."
                )
                return redirect(request.path)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def ajax_required(view_func):
    """
    Decorator to ensure request is AJAX
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
            raise PermissionDenied("This endpoint only accepts AJAX requests.")
        return view_func(request, *args, **kwargs)
    return wrapper


def session_limit(max_sessions=3):
    """
    Decorator to limit concurrent sessions per user
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated:
                active_sessions = request.user.get_active_sessions_count()
                
                if active_sessions >= max_sessions and not request.user.is_superuser:
                    messages.error(
                        request,
                        f"You have reached the maximum of {max_sessions} concurrent sessions. "
                        "Please log out from another device first."
                    )
                    return redirect('accounts:dashboard')
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_2fa_if_enabled(view_func):
    """
    Decorator to ensure 2FA is completed if enabled
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.two_factor_enabled:
            if not request.session.get('2fa_verified', False):
                # Store the intended destination
                request.session['2fa_next'] = request.path
                return redirect('accounts:verify-2fa')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def logout_required(view_func):
    """
    Decorator to require logout (for password change, etc.)
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            # Store flag in session
            request.session['logout_required'] = True
        
        return view_func(request, *args, **kwargs)
    return wrapper


def check_account_lockout(view_func):
    """
    Decorator to check if account is locked before proceeding
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_locked():
            messages.error(
                request,
                f"Your account is locked until "
                f"{request.user.locked_until.strftime('%H:%M')}. "
                "Please try again later."
            )
            return redirect('accounts:login')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def password_expiry_check(view_func):
    """
    Decorator to check if password has expired
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_password_expired():
            messages.warning(
                request,
                "Your password has expired. Please change it to continue."
            )
            return redirect('accounts:change-password')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def security_audit(view_func):
    """
    Decorator to log security events for views
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Log access to sensitive views
        sensitive_views = ['profile', 'security', 'change-password']
        
        view_name = view_func.__name__
        if any(name in view_name for name in sensitive_views):
            from .utils import log_security_event
            log_security_event(
                'SENSITIVE_VIEW_ACCESS',
                user=request.user if request.user.is_authenticated else None,
                request=request,
                metadata={'view': view_name}
            )
        
        return view_func(request, *args, **kwargs)
    return wrapper