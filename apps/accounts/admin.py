from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
import json

from .models import (
    User, UserOTP, UserDevice, 
    SecurityEvent, UserLoginHistory
)


class UserOTPInline(admin.TabularInline):
    """Inline for user OTPs"""
    model = UserOTP
    extra = 0
    readonly_fields = ['otp_code', 'purpose', 'created_at', 'expires_at', 'is_used', 'attempts']
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


class UserDeviceInline(admin.TabularInline):
    """Inline for user devices"""
    model = UserDevice
    extra = 0
    readonly_fields = ['device_id', 'device_type', 'last_used', 'is_trusted']
    can_delete = True


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin"""
    
    list_display = [
        'phone_number', 'get_full_name', 'user_type',
        'is_verified', 'two_factor_enabled', 'is_active',
        'date_joined_display'
    ]
    list_filter = [
        'user_type', 'is_verified', 'two_factor_enabled',
        'is_active', 'is_staff', 'district'
    ]
    search_fields = ['phone_number', 'first_name', 'last_name', 'email']
    ordering = ['-date_joined']
    readonly_fields = [
        'last_login', 'date_joined', 'last_password_change',
        'failed_login_attempts', 'locked_until'
    ]
    
    fieldsets = (
        (None, {
            'fields': ('phone_number', 'password')
        }),
        (_('Personal Information'), {
            'fields': (
                'first_name', 'last_name', 'email',
                'date_of_birth', 'occupation', 'profile_image'
            )
        }),
        (_('Location'), {
            'fields': ('address', 'city', 'district')
        }),
        (_('Account Type'), {
            'fields': ('user_type',)
        }),
        (_('Verification'), {
            'fields': (
                'is_verified', 'verified_at'
            )
        }),
        (_('Two-Factor Authentication'), {
            'fields': (
                'two_factor_enabled', 'two_factor_method',
                'totp_secret'
            )
        }),
        (_('Security Status'), {
            'fields': (
                'failed_login_attempts', 'locked_until',
                'last_password_change', 'last_login', 'last_activity'
            )
        }),
        (_('Permissions'), {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
            )
        }),
        (_('Important Dates'), {
            'fields': ('date_joined',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone_number', 'password1', 'password2'),
        }),
    )
    
    inlines = [UserDeviceInline, UserOTPInline]
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    get_full_name.short_description = 'Name'
    
    def date_joined_display(self, obj):
        return obj.date_joined.strftime('%d %b %Y')
    date_joined_display.short_description = 'Joined'
    date_joined_display.admin_order_field = 'date_joined'
    
    actions = ['verify_users', 'lock_users', 'unlock_users']
    
    def verify_users(self, request, queryset):
        updated = queryset.update(is_verified=True, verified_at=timezone.now())
        self.message_user(request, f'{updated} users were successfully verified.')
    verify_users.short_description = "Verify selected users"
    
    def lock_users(self, request, queryset):
        from datetime import timedelta
        updated = queryset.update(
            locked_until=timezone.now() + timedelta(hours=24)
        )
        self.message_user(request, f'{updated} users were locked.')
    lock_users.short_description = "Lock selected users for 24 hours"
    
    def unlock_users(self, request, queryset):
        updated = queryset.update(
            locked_until=None,
            failed_login_attempts=0
        )
        self.message_user(request, f'{updated} users were unlocked.')
    unlock_users.short_description = "Unlock selected users"


@admin.register(UserOTP)
class UserOTPAdmin(admin.ModelAdmin):
    """Admin for OTP codes"""
    
    list_display = [
        'user', 'purpose', 'otp_code_short',
        'created_at', 'expires_at', 'is_used', 'attempts'
    ]
    list_filter = ['purpose', 'is_used', 'created_at']
    search_fields = ['user__phone_number', 'otp_code']
    readonly_fields = ['created_at', 'expires_at', 'attempts']
    date_hierarchy = 'created_at'
    
    def otp_code_short(self, obj):
        return f"***{obj.otp_code[-3:]}" if obj.otp_code else "-"
    otp_code_short.short_description = 'OTP'


@admin.register(UserDevice)
class UserDeviceAdmin(admin.ModelAdmin):
    """Admin for user devices"""
    
    list_display = [
        'user', 'device_name', 'device_type',
        'last_used', 'is_trusted', 'is_active'
    ]
    list_filter = ['device_type', 'is_trusted', 'is_active']
    search_fields = ['user__phone_number', 'device_id', 'device_name']
    readonly_fields = ['first_seen', 'last_used', 'total_sessions']
    date_hierarchy = 'last_used'
    
    actions = ['trust_devices', 'untrust_devices']
    
    def trust_devices(self, request, queryset):
        from datetime import timedelta
        updated = queryset.update(
            is_trusted=True,
            trusted_until=timezone.now() + timedelta(days=30)
        )
        self.message_user(request, f'{updated} devices trusted.')
    trust_devices.short_description = "Trust selected devices"
    
    def untrust_devices(self, request, queryset):
        updated = queryset.update(is_trusted=False, trusted_until=None)
        self.message_user(request, f'{updated} devices untrusted.')
    untrust_devices.short_description = "Untrust selected devices"


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    """Admin for security events"""
    
    list_display = [
        'user', 'event_type', 'severity',
        'ip_address', 'created_at_short'
    ]
    list_filter = ['event_type', 'severity', 'created_at']
    search_fields = ['user__phone_number', 'ip_address', 'description']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'
    
    def created_at_short(self, obj):
        return obj.created_at.strftime('%d %b %H:%M')
    created_at_short.short_description = 'Time'
    
    def has_add_permission(self, request):
        return False


@admin.register(UserLoginHistory)
class UserLoginHistoryAdmin(admin.ModelAdmin):
    """Admin for login history"""
    
    list_display = [
        'user', 'login_time', 'ip_address',
        'was_successful', 'device_type'
    ]
    list_filter = ['was_successful', 'device_type', 'login_time']
    search_fields = ['user__phone_number', 'ip_address']
    readonly_fields = ['login_time']
    date_hierarchy = 'login_time'
    
    def has_add_permission(self, request):
        return False