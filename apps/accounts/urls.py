from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # OTP Verification
    path('verify-otp/', views.verify_otp_view, name='verify-otp'),
    path('verify-2fa/', views.verify_2fa_view, name='verify-2fa'),
    path('resend-otp/', views.resend_otp_view, name='resend-otp'),
    path('resend-2fa/', views.resend_2fa_view, name='resend-2fa'),
    path('resend-2fa-setup/', views.resend_2fa_setup_view, name='resend-2fa-setup'),
    
    # Dashboard & Profile
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('change-password/', views.change_password_view, name='change-password'),
    
    # Password Reset
    path('request-otp/', views.request_otp_view, name='request-otp'),
    path('password-reset-confirm/', views.password_reset_confirm_view, name='password-reset-confirm'),
    
    # Two-Factor Authentication
    path('setup-2fa/', views.setup_2fa_view, name='setup-2fa'),
    path('disable-2fa/', views.disable_2fa_view, name='disable-2fa'),
    path('2fa-recovery/', views.two_factor_recovery_view, name='2fa-recovery'),
    path('generate-backup-codes/', views.generate_backup_codes_view, name='generate-backup-codes'),
    
    # Security & Devices
    path('security/', views.security_view, name='security'),
    path('trusted-devices/', views.trusted_devices_view, name='trusted-devices'),
    path('trust-all-devices/', views.trust_all_devices_view, name='trust-all-devices'),
    path('revoke-device/<int:device_id>/', views.revoke_device_view, name='revoke-device'),
    path('activity-log/', views.activity_log_view, name='activity-log'),
    
    # Account Management
    path('delete-account/', views.delete_account_view, name='delete-account'),
    path('deactivate-account/', views.deactivate_account_view, name='deactivate-account'),
    
    # API Endpoints (AJAX)
    path('api/check-username/', views.check_username_api, name='check-username'),
    path('api/check-email/', views.check_email_api, name='check-email'),
    path('api/update-profile/', views.update_profile_api, name='update-profile'),
]