from django import forms
from django.contrib.auth.forms import PasswordChangeForm as AuthPasswordChangeForm
from django.contrib.auth.forms import PasswordResetForm
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.validators import RegexValidator
import re

from .models import User, UserOTP
from .utils import validate_sl_phone, normalize_phone, check_password_strength


class UserRegistrationForm(forms.ModelForm):
    """
    Form for user registration with comprehensive validation
    """
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Create a strong password',
            'id': 'password',
            'autocomplete': 'new-password'
        }),
        label='Password',
        help_text='Minimum 8 characters with uppercase, lowercase, number, and special character'
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Confirm your password',
            'id': 'password2',
            'autocomplete': 'new-password'
        }),
        label='Confirm Password'
    )
    agree_terms = forms.BooleanField(
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-sl-green focus:ring-sl-green border-gray-300 rounded'
        }),
        label='I agree to the Terms of Service and Privacy Policy',
        error_messages={
            'required': 'You must agree to the terms and conditions to register.'
        }
    )
    
    class Meta:
        model = User
        fields = ['phone_number', 'first_name', 'last_name', 'email']
        widgets = {
            'phone_number': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': '76 123 456',
                'id': 'phone_number',
                'autocomplete': 'tel'
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'John',
                'id': 'first_name',
                'autocomplete': 'given-name'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Doe',
                'id': 'last_name',
                'autocomplete': 'family-name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': 'john@example.com',
                'id': 'email',
                'autocomplete': 'email'
            }),
        }
    
    def clean_phone_number(self):
        """Validate and normalize phone number"""
        phone = self.cleaned_data.get('phone_number')
        
        if not phone:
            raise ValidationError('Phone number is required.')
        
        # Remove spaces and formatting
        phone = re.sub(r'[\s\-\(\)]', '', phone)
        
        # Validate Sierra Leone format
        if not validate_sl_phone(phone):
            raise ValidationError(
                'Invalid Sierra Leone phone number. Please use format: 076123456 or +23276123456'
            )
        
        # Normalize
        phone = normalize_phone(phone)
        
        # Check uniqueness
        if User.objects.filter(phone_number=phone).exists():
            raise ValidationError('This phone number is already registered.')
        
        return phone
    
    def clean_email(self):
        """Validate email (optional but must be unique if provided)"""
        email = self.cleaned_data.get('email')
        
        if email:
            email = email.lower().strip()
            if User.objects.filter(email=email).exists():
                raise ValidationError('This email address is already registered.')
        
        return email
    
    def clean_password(self):
        """Validate password strength"""
        password = self.cleaned_data.get('password')
        
        if password:
            is_valid, error = check_password_strength(password)
            if not is_valid:
                raise ValidationError(error)
        
        return password
    
    def clean(self):
        """Validate password match"""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password2 = cleaned_data.get('password2')
        
        if password and password2 and password != password2:
            raise ValidationError({'password2': 'Passwords do not match.'})
        
        return cleaned_data
    
    def save(self, commit=True):
        """Save user with hashed password"""
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        user.is_active = False  # Require OTP verification
        
        if commit:
            user.save()
        
        return user


class UserLoginForm(forms.Form):
    """
    Form for user login with rate limiting support
    """
    phone_number = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': '76 123 456',
            'id': 'phone_number',
            'autocomplete': 'tel'
        }),
        label='Phone Number'
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Enter your password',
            'id': 'password',
            'autocomplete': 'current-password'
        }),
        label='Password'
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-sl-blue focus:ring-sl-blue border-gray-300 rounded'
        }),
        label='Remember me for 30 days'
    )
    
    def clean_phone_number(self):
        """Normalize phone number"""
        phone = self.cleaned_data.get('phone_number')
        if phone:
            phone = re.sub(r'[\s\-\(\)]', '', phone)
            phone = normalize_phone(phone)
        return phone


class UserProfileForm(forms.ModelForm):
    """
    Form for editing user profile
    """
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'date_of_birth',
            'occupation', 'address', 'city', 'district', 'profile_image'
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-input',
                'id': 'first_name'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input',
                'id': 'last_name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'id': 'email',
                'autocomplete': 'email'
            }),
            'date_of_birth': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
                'id': 'date_of_birth',
                'max': timezone.now().date().isoformat()
            }),
            'occupation': forms.TextInput(attrs={
                'class': 'form-input',
                'id': 'occupation'
            }),
            'address': forms.Textarea(attrs={
                'class': 'form-input',
                'rows': 3,
                'id': 'address',
                'placeholder': 'Street address'
            }),
            'city': forms.TextInput(attrs={
                'class': 'form-input',
                'id': 'city',
                'placeholder': 'City/Town'
            }),
            'district': forms.Select(attrs={
                'class': 'form-input',
                'id': 'district'
            }),
            'profile_image': forms.FileInput(attrs={
                'class': 'form-input',
                'id': 'profile_image',
                'accept': 'image/jpeg,image/png,image/gif'
            }),
        }
    
    def clean_email(self):
        """Ensure email is unique if provided"""
        email = self.cleaned_data.get('email')
        if email:
            email = email.lower().strip()
            
            # Check if email exists for another user
            if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
                raise ValidationError('This email address is already in use.')
        
        return email
    
    def clean_profile_image(self):
        """Validate profile image"""
        image = self.cleaned_data.get('profile_image')
        if image:
            # Check file size (max 5MB)
            if image.size > 5 * 1024 * 1024:
                raise ValidationError('Image file too large (max 5MB)')
            
            # Check file type
            if not image.content_type.startswith('image/'):
                raise ValidationError('File must be an image')
        
        return image


class OTPVerificationForm(forms.Form):
    """
    Form for OTP verification
    """
    otp_code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-2xl tracking-widest',
            'placeholder': '• • • • • •',
            'id': 'otp_code',
            'autocomplete': 'off',
            'inputmode': 'numeric',
            'pattern': '[0-9]*'
        }),
        label='Verification Code',
        error_messages={
            'min_length': 'OTP must be exactly 6 digits.',
            'max_length': 'OTP must be exactly 6 digits.',
        }
    )
    
    def clean_otp_code(self):
        """Validate OTP format"""
        otp = self.cleaned_data.get('otp_code')
        if otp and not otp.isdigit():
            raise ValidationError('OTP must contain only numbers.')
        return otp


class PasswordChangeForm(AuthPasswordChangeForm):
    """
    Custom password change form with enhanced validation
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.fields['old_password'].widget.attrs.update({
            'class': 'form-input',
            'id': 'old_password',
            'placeholder': 'Enter current password',
            'autocomplete': 'current-password'
        })
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-input',
            'id': 'new_password1',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password'
        })
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-input',
            'id': 'new_password2',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password'
        })
    
    def clean_new_password1(self):
        """Validate new password strength"""
        password = self.cleaned_data.get('new_password1')
        
        if password:
            is_valid, error = check_password_strength(password)
            if not is_valid:
                raise ValidationError(error)
            
            # Check if password was used before
            if self.user.is_password_reused(password):
                raise ValidationError('You have used this password recently. Please choose a different password.')
        
        return password


class PhoneNumberForm(forms.Form):
    """
    Form for entering phone number (password reset, etc.)
    """
    phone_number = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': '76 123 456',
            'id': 'phone_number',
            'autocomplete': 'tel'
        }),
        label='Phone Number'
    )
    
    def clean_phone_number(self):
        """Validate and normalize phone number"""
        phone = self.cleaned_data.get('phone_number')
        
        if not phone:
            raise ValidationError('Phone number is required.')
        
        # Remove spaces and formatting
        phone = re.sub(r'[\s\-\(\)]', '', phone)
        
        # Validate format
        if not validate_sl_phone(phone):
            raise ValidationError('Invalid Sierra Leone phone number format.')
        
        # Normalize
        phone = normalize_phone(phone)
        
        # Check if user exists
        if not User.objects.filter(phone_number=phone).exists():
            raise ValidationError('No account found with this phone number.')
        
        return phone


class TwoFactorSetupForm(forms.Form):
    """
    Form for setting up two-factor authentication
    """
    method = forms.ChoiceField(
        choices=[
            ('SMS', 'SMS - Receive codes via text message'),
            ('TOTP', 'Authenticator App - Use Google Authenticator, Authy, etc.'),
        ],
        widget=forms.RadioSelect(attrs={
            'class': 'h-4 w-4 text-sl-blue focus:ring-sl-blue'
        }),
        initial='SMS',
        label='Verification Method'
    )
    otp_code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-2xl tracking-widest',
            'placeholder': '• • • • • •',
            'id': 'otp_code',
            'autocomplete': 'off',
            'inputmode': 'numeric'
        }),
        label='Verification Code',
        help_text='Enter the 6-digit code sent to your phone'
    )
    
    def clean_otp_code(self):
        """Validate OTP format"""
        otp = self.cleaned_data.get('otp_code')
        if otp and not otp.isdigit():
            raise ValidationError('OTP must contain only numbers.')
        return otp


class TwoFactorVerifyForm(forms.Form):
    """
    Form for verifying 2FA during login
    """
    otp_code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-2xl tracking-widest',
            'placeholder': '• • • • • •',
            'id': 'otp_code',
            'autocomplete': 'off',
            'inputmode': 'numeric',
            'autofocus': True
        }),
        label='Authentication Code'
    )
    trust_device = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-sl-green focus:ring-sl-green border-gray-300 rounded'
        }),
        label='Trust this device for 30 days'
    )
    
    def clean_otp_code(self):
        """Validate OTP format"""
        otp = self.cleaned_data.get('otp_code')
        if otp and not otp.isdigit():
            raise ValidationError('Code must contain only numbers.')
        return otp


class ResendOTPForm(forms.Form):
    """
    Form for resending OTP
    """
    phone_number = forms.CharField(widget=forms.HiddenInput())
    purpose = forms.ChoiceField(
        choices=UserOTP.Purpose.choices,
        widget=forms.HiddenInput()
    )


class BackupCodeForm(forms.Form):
    """
    Form for using backup codes
    """
    backup_code = forms.CharField(
        max_length=8,
        min_length=8,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center uppercase tracking-wider',
            'placeholder': 'XXXXXXXX',
            'id': 'backup_code',
            'autocomplete': 'off',
            'autofocus': True
        }),
        label='Backup Code',
        help_text='Enter one of your 8-character backup codes'
    )
    
    def clean_backup_code(self):
        """Normalize backup code"""
        code = self.cleaned_data.get('backup_code')
        if code:
            code = code.upper().strip()
        return code


class Disable2FAForm(forms.Form):
    """
    Form for disabling two-factor authentication
    """
    otp_code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-2xl tracking-widest',
            'placeholder': '• • • • • •',
            'id': 'otp_code',
            'autocomplete': 'off',
            'inputmode': 'numeric'
        }),
        label='Verification Code'
    )
    confirm = forms.BooleanField(
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-red-600 focus:ring-red-500 border-gray-300 rounded'
        }),
        label='I understand that disabling 2FA makes my account less secure',
        error_messages={
            'required': 'You must confirm that you understand the security implications.'
        }
    )
    
    def clean_otp_code(self):
        """Validate OTP format"""
        otp = self.cleaned_data.get('otp_code')
        if otp and not otp.isdigit():
            raise ValidationError('OTP must contain only numbers.')
        return otp