import pyotp
import getpass
import qrcode
import os

# Step 1: Registration - User sets up MFA
def register_mfa():
    # Generate a new secret key for the user
    secret_key = pyotp.random_base32()

    # Create a TOTP instance
    totp = pyotp.TOTP(secret_key)

    print("Your secret key is:", secret_key)
    provisioning_uri = totp.provisioning_uri("simple_mfa", "kyawthethanjun30@gmail.com")
    
    # Create a QR code for the provisioning URI
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    # Create and display the QR code
    qr_code = qr.make_image(fill_color="black", back_color="white")
    qr_code.save("qrcode.png")
    os.system("qrcode.png")
    return secret_key

# Step 2: Authentication - User logs in with MFA
def authenticate_mfa(secret_key):
    # Create a TOTP instance
    totp = pyotp.TOTP(secret_key)

    # Ask the user for their OTP code
    otp = input("Enter your one-time password (OTP) from your authenticator app: ")

    # Verify the OTP code
    if totp.verify(otp):
        print("Authentication successful!")
    else:
        print("Authentication failed. Please try again.")

if __name__ == "__main__":
    print("Multi-Factor Authentication (MFA) Example")

    # Step 1: User registration (run this once)
    secret_key = register_mfa()
    
    # Step 2: User authentication (run this when user logs in)
    password = getpass.getpass("Enter your password: ")

    # In a real-world scenario, you'd validate the password here.
    # For simplicity, we'll assume the password is correct.

    # Authenticate with MFA
    authenticate_mfa(secret_key)
