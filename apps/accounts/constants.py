
# Add required constants file (constants.py)
# constants.py
OTP_PURPOSES = {
    'REGISTER': 'REGISTER',
    'RESET_PASSWORD': 'RESET_PASSWORD',
    'TWO_FACTOR': 'TWO_FACTOR',
    'TWO_FACTOR_SETUP': 'TWO_FACTOR_SETUP',
    'TWO_FACTOR_DISABLE': 'TWO_FACTOR_DISABLE',
}

MAX_OTP_ATTEMPTS = 3
OTP_RATE_LIMIT = {
    'max_attempts': 3,
    'timeout': 3600
}

SESSION_KEYS = {
    'VERIFICATION_PHONE': 'verification_phone',
    'VERIFICATION_PURPOSE': 'verification_purpose',
    'TWO_FACTOR_USER_ID': '2fa_user_id',
    'TWO_FACTOR_REMEMBER': '2fa_remember',
    'RESET_VERIFIED': 'reset_verified',
}

DEVICE_TYPES = {
    'WEB': 'WEB',
    'MOBILE': 'MOBILE',
    'TABLET': 'TABLET',
}