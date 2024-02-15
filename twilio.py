import os
from twilio.rest import Client

# Twillo
# YLLWKXB6RDJW89MFFDK4SFJP

# Auth token: 81fd385cc7944a385cf147e61eb0f21f

# Set environment variables for your credentials
# Read more at http://twil.io/secure
account_sid = "ACf90974bece8ec9d18cc29026f3679f02"
auth_token = "81fd385cc7944a385cf147e61eb0f21f"  # os.environ["TWILIO_AUTH_TOKEN"]
verify_sid = "VAc247dbc801a2ef38e218d2e45bd50fbc"
verified_number = "+14236912822"

client = Client(account_sid, auth_token)

verification = client.verify.v2.services(verify_sid).verifications.create(
    to=verified_number, channel="sms"
)
print(verification.status)

otp_code = input("Please enter the OTP:")

verification_check = client.verify.v2.services(verify_sid).verification_checks.create(
    to=verified_number, code=otp_code
)
print(verification_check.status)
