from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from django.core.cache import cache
import re
import secrets
from datetime import timedelta

from apps.accounts.models import User, UserOTP, UserDevice, UserManager


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = [
            'phone_number', 'email', 'first_name', 'last_name',
            'password', 'password2'
        ]
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': False}
        }
    
    def validate_phone_number(self, value):
        """Validate Sierra Leone phone number"""
        # Rate limiting check
        request = self.context.get('request')
        if request:
            ip = request.META.get('REMOTE_ADDR')
            cache_key = f"reg_ip_{ip}"
            attempts = cache.get(cache_key, 0)
            
            if attempts >= 5:
                raise serializers.ValidationError(
                    "Too many registration attempts. Please try again later."
                )
            
            # Increment attempt counter
            cache.set(cache_key, attempts + 1, 3600)
        
        # Normalize and validate
        phone = re.sub(r'[\s\-\(\)]', '', value)
        
        # Check if already exists
        if User.objects.filter(phone_number=phone).exists():
            raise serializers.ValidationError("User with this phone number already exists")
        
        return phone
    
    def validate_password(self, value):
        """Additional password strength validation"""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter"
            )
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter"
            )
        
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        return value
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match"})
        return attrs
    
    def create(self, validated_data):
        """Create user and generate OTP"""
        validated_data.pop('password2')
        
        # Normalize phone number
        validated_data['phone_number'] = UserManager.normalize_phone(
            validated_data['phone_number']
        )
        
        user = User.objects.create_user(**validated_data)
        
        # Generate OTP for verification
        self.generate_otp(user)
        
        return user
    
    def generate_otp(self, user):
        """Generate 6-digit OTP"""
        request = self.context.get('request')
        otp_code = ''.join(secrets.choice('0123456789') for _ in range(6))
        
        UserOTP.objects.create(
            user=user,
            otp_code=otp_code,
            purpose=UserOTP.Purpose.REGISTER,
            ip_address=request.META.get('REMOTE_ADDR') if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else ''
        )
        
        # TODO: Send SMS with OTP
        print(f"OTP for {user.phone_number}: {otp_code}")  # For development
        
        return otp_code


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    
    phone_number = serializers.CharField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        phone = attrs.get('phone_number')
        password = attrs.get('password')
        request = self.context.get('request')
        
        if not phone or not password:
            raise serializers.ValidationError("Phone number and password are required")
        
        # Rate limiting by IP
        if request:
            ip = request.META.get('REMOTE_ADDR')
            cache_key = f"login_ip_{ip}"
            attempts = cache.get(cache_key, 0)
            
            if attempts >= 10:
                raise serializers.ValidationError(
                    "Too many login attempts. Please try again later."
                )
        
        # Normalize phone
        phone = UserManager.normalize_phone(phone)
        
        # Authenticate
        user = authenticate(request=request, username=phone, password=password)
        
        if not user:
            # Increment IP rate limit
            if request:
                cache.set(cache_key, attempts + 1, 3600)
            raise serializers.ValidationError("Invalid phone number or password")
        
        # Check if account is locked
        if user.is_locked():
            raise serializers.ValidationError(
                "Account is locked due to too many failed attempts. Please try again later."
            )
        
        # Check if user is active
        if not user.is_active:
            raise serializers.ValidationError("Account is disabled")
        
        # Check if 2FA is required
        if user.requires_2fa():
            attrs['requires_2fa'] = True
            attrs['user'] = user
            return attrs
        
        attrs['user'] = user
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile"""
    
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'phone_number', 'email', 'first_name', 'last_name',
            'full_name', 'profile_image', 'date_of_birth', 'occupation',
            'address', 'city', 'district', 'is_verified', 'user_type',
            'two_factor_enabled', 'two_factor_method', 'date_joined', 'last_login'
        ]
        read_only_fields = ['id', 'phone_number', 'is_verified', 'user_type', 'date_joined', 'last_login']
    
    def get_full_name(self, obj):
        return obj.get_full_name()


class VerifyOTPSerializer(serializers.Serializer):
    """Serializer for OTP verification"""
    
    phone_number = serializers.CharField()
    otp_code = serializers.CharField(max_length=6)
    
    def validate_otp_code(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be 6 digits")
        return value
    
    def validate(self, attrs):
        phone = attrs.get('phone_number')
        otp_code = attrs.get('otp_code')
        
        # Normalize phone
        phone = UserManager.normalize_phone(phone)
        
        try:
            user = User.objects.get(phone_number=phone)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Get latest OTP
        try:
            otp = UserOTP.objects.filter(
                user=user,
                purpose=UserOTP.Purpose.REGISTER,
                is_used=False,
                expires_at__gt=timezone.now()
            ).latest('created_at')
        except UserOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired OTP")
        
        if otp.otp_code != otp_code:
            raise serializers.ValidationError("Invalid OTP code")
        
        attrs['user'] = user
        attrs['otp'] = otp
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change"""
    
    old_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    new_password2 = serializers.CharField(write_only=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "Passwords didn't match"})
        
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError(
                {"new_password": "New password must be different from old password"}
            )
        
        return attrs


class RequestOTPSerializer(serializers.Serializer):
    """Serializer for requesting OTP"""
    
    phone_number = serializers.CharField()
    purpose = serializers.ChoiceField(choices=['LOGIN', 'RESET_PASSWORD'])
    
    def validate_phone_number(self, value):
        phone = UserManager.normalize_phone(value)
        
        try:
            user = User.objects.get(phone_number=phone)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        return phone
    
    def validate(self, attrs):
        # Rate limiting
        request = self.context.get('request')
        if request:
            ip = request.META.get('REMOTE_ADDR')
            cache_key = f"otp_request_ip_{ip}"
            attempts = cache.get(cache_key, 0)
            
            if attempts >= 3:  # Max 3 OTP requests per hour
                raise serializers.ValidationError(
                    "Too many OTP requests. Please try again later."
                )
            
            cache.set(cache_key, attempts + 1, 3600)
        
        return attrs


class TwoFactorVerifySerializer(serializers.Serializer):
    """Serializer for 2FA verification"""
    
    user_id = serializers.IntegerField()
    otp_code = serializers.CharField(max_length=6)
    
    def validate_otp_code(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be 6 digits")
        return value
    
    def validate(self, attrs):
        user_id = attrs.get('user_id')
        otp_code = attrs.get('otp_code')
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Verify SMS OTP
        if user.two_factor_method == 'SMS':
            try:
                otp = UserOTP.objects.filter(
                    user=user,
                    purpose=UserOTP.Purpose.TWO_FACTOR,
                    is_used=False,
                    expires_at__gt=timezone.now()
                ).latest('created_at')
                
                if otp.otp_code != otp_code:
                    raise serializers.ValidationError("Invalid OTP code")
                
                otp.is_used = True
                otp.save()
                attrs['user'] = user
                
            except UserOTP.DoesNotExist:
                raise serializers.ValidationError("Invalid or expired OTP")
        
        return attrs