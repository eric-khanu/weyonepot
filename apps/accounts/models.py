from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
import re
import secrets
import hashlib
from datetime import timedelta

try:
    from encrypted_model_fields.fields import EncryptedCharField
except ImportError:
    # Fallback if encrypted fields not installed
    from django.db.models import CharField as EncryptedCharField


class UserManager(BaseUserManager):
    """Custom user manager with enhanced security features"""
    
    def create_user(self, phone_number, password=None, **extra_fields):
        """Create and save a regular user"""
        if not phone_number:
            raise ValueError(_('Phone number is required'))
        
        # Normalize phone number
        phone_number = self.normalize_phone(phone_number)
        
        # Validate Sierra Leone phone number
        if not self.validate_sl_phone(phone_number):
            raise ValueError(_('Invalid Sierra Leone phone number format'))
        
        user = self.model(phone_number=phone_number, **extra_fields)
        
        if password:
            user.set_password(password)
        else:
            # Generate secure random password for OTP-only users
            user.set_password(secrets.token_urlsafe(32))
        
        # Set initial security fields
        user.security_profile = {
            'password_last_changed': timezone.now().isoformat(),
            'registration_ip': extra_fields.pop('registration_ip', None),
            'registration_date': timezone.now().isoformat(),
            'failed_attempts': 0,
            'password_history': []
        }
        
        user.save(using=self._db)
        return user
    
    def create_superuser(self, phone_number, password=None, **extra_fields):
        """Create superuser with admin privileges"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('user_type', 'ADMIN')
        
        return self.create_user(phone_number, password, **extra_fields)
    
    @staticmethod
    def normalize_phone(phone):
        """Normalize phone number to standard format"""
        if not phone:
            return phone
        
        # Remove spaces, dashes, parentheses
        phone = re.sub(r'[\s\-\(\)]', '', phone)
        
        # Remove any non-digit characters except leading +
        phone = re.sub(r'[^\d+]', '', phone)
        
        # Convert to 0 format for storage
        if phone.startswith('+232'):
            phone = '0' + phone[4:]
        elif phone.startswith('232'):
            phone = '0' + phone[3:]
        
        # Ensure it's 10 digits (0 + 9 digits)
        if len(phone) == 9 and not phone.startswith('0'):
            phone = '0' + phone
        
        return phone
    
    @staticmethod
    def validate_sl_phone(phone):
        """Validate Sierra Leone phone numbers"""
        if not phone:
            return False
        
        # Remove spaces and dashes
        phone = re.sub(r'[\s\-\(\)]', '', phone)
        
        # Sierra Leone prefixes: 76,77,78,79,30,31,32,33,34,88,99
        pattern = r'^(?:(?:\+?232)|0)?(76|77|78|79|30|31|32|33|34|88|99)[0-9]{6}$'
        return bool(re.match(pattern, phone))


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model with security features"""
    
    class UserType(models.TextChoices):
        INDIVIDUAL = 'INDIVIDUAL', 'Individual Saver'
        GROUP_ADMIN = 'GROUP_ADMIN', 'Group Administrator'
        ADMIN = 'ADMIN', 'System Administrator'
    
    # Basic Information
    phone_number = models.CharField(
        max_length=15,
        unique=True,
        db_index=True,
        help_text='Sierra Leone phone number (e.g., 076123456)'
    )
    email = models.EmailField(blank=True, null=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    
    # Account Type
    user_type = models.CharField(
        max_length=20,
        choices=UserType.choices,
        default=UserType.INDIVIDUAL,
        db_index=True
    )
    
    # Profile Information
    profile_image = models.ImageField(
        upload_to='profiles/%Y/%m/',
        null=True,
        blank=True
    )
    date_of_birth = models.DateField(null=True, blank=True)
    occupation = models.CharField(max_length=100, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    district = models.CharField(
        max_length=50,
        choices=[
            ('western_urban', 'Western Area Urban'),
            ('western_rural', 'Western Area Rural'),
            ('northern', 'Northern Province'),
            ('southern', 'Southern Province'),
            ('eastern', 'Eastern Province'),
            ('north_west', 'North West Province'),
        ],
        blank=True
    )
    
    # KYC/Verification
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Two-Factor Authentication
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_method = models.CharField(
        max_length=20,
        choices=[
            ('SMS', 'SMS Verification'),
            ('TOTP', 'Authenticator App'),
        ],
        default='SMS'
    )
    totp_secret = models.CharField(
        max_length=255,
        blank=True,
        help_text='TOTP secret key for authenticator apps'
    )
    backup_codes = models.JSONField(
        default=list,
        help_text='Hashed backup codes for 2FA recovery'
    )
    
    # Account Status
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    last_password_change = models.DateTimeField(default=timezone.now)
    
    # Security Tracking
    security_profile = models.JSONField(default=dict)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # Notification Preferences
    preferred_language = models.CharField(
        max_length=10,
        choices=[('en', 'English'), ('krio', 'Krio')],
        default='en'
    )
    notification_preferences = models.JSONField(default=dict)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['phone_number', 'is_active']),
            models.Index(fields=['user_type']),
            models.Index(fields=['-date_joined']),
        ]
    
    def __str__(self):
        return f"{self.phone_number}"
    
    def save(self, *args, **kwargs):
        """Override save to add security checks"""
        # Track if password changed
        if self.pk:
            try:
                old = User.objects.get(pk=self.pk)
                if old.password != self.password:
                    self.password_changed()
            except User.DoesNotExist:
                pass
        
        # Normalize phone before save
        if self.phone_number:
            self.phone_number = UserManager.normalize_phone(self.phone_number)
        
        super().save(*args, **kwargs)
    
    def get_full_name(self):
        """Return full name safely"""
        if self.first_name or self.last_name:
            return f"{self.first_name or ''} {self.last_name or ''}".strip()
        return f"User {self.phone_number[-4:]}"
    
    def get_short_name(self):
        """Return short name"""
        return self.first_name or f"User {self.phone_number[-4:]}"
    
    def update_last_activity(self):
        """Update last activity timestamp"""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])
    
    def get_normalized_phone(self):
        """Return phone in international format"""
        if self.phone_number.startswith('0'):
            return '+232' + self.phone_number[1:]
        return self.phone_number
    
    # ========== SECURITY METHODS ==========
    
    def check_password(self, raw_password):
        """Enhanced password check with security logging"""
        # Check if account is locked
        if self.is_locked():
            return False
        
        result = super().check_password(raw_password)
        
        if not result:
            self.failed_login_attempts += 1
            
            # Auto-lock after too many failures
            if self.failed_login_attempts >= 5:
                self.locked_until = timezone.now() + timedelta(minutes=30)
            
            self.save(update_fields=['failed_login_attempts', 'locked_until'])
        else:
            # Reset on success
            if self.failed_login_attempts > 0 or self.locked_until:
                self.failed_login_attempts = 0
                self.locked_until = None
                self.save(update_fields=['failed_login_attempts', 'locked_until'])
        
        return result
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False
    
    def password_changed(self):
        """Handle password change with history tracking"""
        from django.contrib.auth.hashers import make_password
        
        self.last_password_change = timezone.now()
        
        # Initialize security profile if needed
        if not self.security_profile:
            self.security_profile = {}
        
        # Track password history (last 5 passwords)
        password_history = self.security_profile.get('password_history', [])
        
        # Store current password hash in history
        if self.password:
            password_history = [self.password] + password_history[:4]
        
        self.security_profile['password_history'] = password_history
        self.security_profile['password_last_changed'] = timezone.now().isoformat()
    
    def is_password_expired(self):
        """Check if password needs to be changed"""
        expiry_days = 90  # 90 days password expiry
        expiry_date = self.last_password_change + timedelta(days=expiry_days)
        return timezone.now() > expiry_date
    
    def is_password_reused(self, new_password):
        """Check if password was used recently"""
        from django.contrib.auth.hashers import check_password
        
        password_history = self.security_profile.get('password_history', [])
        for old_hash in password_history:
            if check_password(new_password, old_hash):
                return True
        return False
    
    def generate_backup_codes(self, count=8):
        """Generate one-time backup codes for 2FA"""
        codes = []
        hashed_codes = []
        
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            codes.append(code)
            # Store hashed version
            hashed_codes.append(hashlib.sha256(code.encode()).hexdigest())
        
        self.backup_codes = hashed_codes
        self.save(update_fields=['backup_codes'])
        
        return codes  # Return plain codes to show user
    
    def verify_backup_code(self, code):
        """Verify a backup code and consume it"""
        if not self.backup_codes:
            return False
        
        hashed = hashlib.sha256(code.upper().encode()).hexdigest()
        
        if hashed in self.backup_codes:
            # Remove used code
            self.backup_codes.remove(hashed)
            self.save(update_fields=['backup_codes'])
            return True
        
        return False
    
    def requires_2fa(self):
        """Check if user requires 2FA"""
        return self.two_factor_enabled or self.user_type == self.UserType.ADMIN


class UserOTP(models.Model):
    """Model for storing OTP codes"""
    
    class Purpose(models.TextChoices):
        LOGIN = 'LOGIN', 'Login Verification'
        REGISTER = 'REGISTER', 'Registration Verification'
        RESET_PASSWORD = 'RESET_PASSWORD', 'Password Reset'
        TWO_FACTOR = 'TWO_FACTOR', 'Two-Factor Auth'
        TWO_FACTOR_SETUP = 'TWO_FACTOR_SETUP', '2FA Setup'
        TWO_FACTOR_DISABLE = 'TWO_FACTOR_DISABLE', '2FA Disable'
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='otps'
    )
    otp_code = models.CharField(max_length=6)
    purpose = models.CharField(
        max_length=30,
        choices=Purpose.choices,
        db_index=True
    )
    
    # Context
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)
    
    # Status
    is_used = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['otp_code', 'is_used']),
            models.Index(fields=['expires_at']),
        ]
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        """Override save to set expiry if not set"""
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)
    
    @property
    def is_valid(self):
        """Check if OTP is still valid"""
        return (
            not self.is_used and
            self.attempts < 3 and
            timezone.now() < self.expires_at
        )
    
    def verify(self, code):
        """Verify OTP code with attempt tracking"""
        self.attempts += 1
        
        if self.attempts >= 3:
            self.is_used = True  # Lock after too many attempts
        
        if self.is_valid and self.otp_code == code:
            self.is_used = True
            self.save(update_fields=['is_used', 'attempts'])
            return True
        
        self.save(update_fields=['attempts'])
        return False


class UserDevice(models.Model):
    """Track and manage user devices"""
    
    class DeviceType(models.TextChoices):
        MOBILE = 'MOBILE', 'Mobile App'
        WEB = 'WEB', 'Web Browser'
        USSD = 'USSD', 'USSD'
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='devices'
    )
    device_id = models.CharField(max_length=255, db_index=True)
    device_name = models.CharField(max_length=255, blank=True)
    device_type = models.CharField(
        max_length=20,
        choices=DeviceType.choices,
        default='WEB'
    )
    
    # Security context
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Trust status
    is_trusted = models.BooleanField(default=False)
    trusted_until = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Statistics
    total_sessions = models.IntegerField(default=0)
    
    # Timestamps
    first_seen = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['user', 'device_id']
        indexes = [
            models.Index(fields=['user', '-last_used']),
            models.Index(fields=['device_id']),
        ]
    
    def __str__(self):
        return f"{self.user.phone_number} - {self.device_name or self.device_type}"
    
    def save(self, *args, **kwargs):
        """Set trusted expiry if trusted"""
        if self.is_trusted and not self.trusted_until:
            self.trusted_until = timezone.now() + timedelta(days=30)
        super().save(*args, **kwargs)
    
    def update_usage(self, ip=None, user_agent=None):
        """Update device usage information"""
        self.last_used = timezone.now()
        self.total_sessions += 1
        
        if ip:
            self.ip_address = ip
        if user_agent:
            self.user_agent = user_agent
        
        self.save(update_fields=['last_used', 'total_sessions', 'ip_address', 'user_agent'])
    
    def is_trusted_valid(self):
        """Check if trust is still valid"""
        return (
            self.is_trusted and
            self.trusted_until and
            self.trusted_until > timezone.now()
        )


class SecurityEvent(models.Model):
    """Track all security-related events"""
    
    class EventType(models.TextChoices):
        LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Login Successful'
        LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'
        LOGOUT = 'LOGOUT', 'Logout'
        PASSWORD_CHANGED = 'PASSWORD_CHANGED', 'Password Changed'
        PASSWORD_RESET = 'PASSWORD_RESET', 'Password Reset'
        TWO_FACTOR_ENABLED = '2FA_ENABLED', '2FA Enabled'
        TWO_FACTOR_DISABLED = '2FA_DISABLED', '2FA Disabled'
        TWO_FACTOR_RECOVERY = '2FA_RECOVERY', '2FA Recovery Used'
        DEVICE_TRUSTED = 'DEVICE_TRUSTED', 'Device Trusted'
        DEVICE_REVOKED = 'DEVICE_REVOKED', 'Device Revoked'
        ACCOUNT_LOCKED = 'ACCOUNT_LOCKED', 'Account Locked'
        ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED', 'Account Unlocked'
        PROFILE_UPDATED = 'PROFILE_UPDATED', 'Profile Updated'
        USER_REGISTERED = 'USER_REGISTERED', 'User Registered'
        USER_VERIFIED = 'USER_VERIFIED', 'User Verified'
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='security_events',
        null=True,
        blank=True
    )
    event_type = models.CharField(
        max_length=50,
        choices=EventType.choices,
        db_index=True
    )
    
    # Context
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.TextField(blank=True)
    
    # Details
    metadata = models.JSONField(default=dict)
    description = models.TextField(blank=True)
    
    # Severity
    severity = models.CharField(
        max_length=20,
        choices=[
            ('INFO', 'Info'),
            ('WARNING', 'Warning'),
            ('CRITICAL', 'Critical'),
        ],
        default='INFO'
    )
    
    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['event_type', 'created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        user_info = self.user.phone_number if self.user else 'Anonymous'
        return f"{user_info} - {self.event_type} at {self.created_at}"


class UserLoginHistory(models.Model):
    """Track user login history"""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='login_history'
    )
    
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Result
    was_successful = models.BooleanField(default=True)
    failure_reason = models.CharField(max_length=255, blank=True)
    
    # Device info
    device_id = models.CharField(max_length=255, blank=True)
    device_type = models.CharField(max_length=50, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', '-login_time']),
        ]
        ordering = ['-login_time']
    
    def __str__(self):
        status = "Success" if self.was_successful else f"Failed: {self.failure_reason}"
        return f"{self.user.phone_number} - {self.login_time} - {status}"