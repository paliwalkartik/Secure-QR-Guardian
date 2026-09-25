import os
import sys
import subprocess

# Ensure we can import modules from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Auto-install qrcode library for generating the test fixture if it's missing
try:
    import qrcode
except ImportError:
    print("qrcode library not found. Installing it for the test fixture...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode[pil]", "-q"])
    import qrcode

from core.scanner.sanitizer import sanitize
from core.scanner.payload_models import SanitizedPayload, DataType
from core.scanner.qr_scanner import QRScanner

def main():
    print("--- 1. Testing sanitize() Function ---")
    p_upi = sanitize("paytm@ybl")
    assert p_upi.data_type == DataType.UPI, f"Expected UPI, got {p_upi.data_type}"
    
    p_url = sanitize("https://evil.com/pay")
    assert p_url.data_type == DataType.URL, f"Expected URL, got {p_url.data_type}"
    
    p_text = sanitize("Hello World")
    assert p_text.data_type == DataType.TEXT, f"Expected TEXT, got {p_text.data_type}"
    
    p_unk = sanitize("")
    assert p_unk.data_type == DataType.UNKNOWN, f"Expected UNKNOWN, got {p_unk.data_type}"
    print("sanitize() OK.")

    print("\n--- 2. Testing SanitizedPayload.is_actionable() ---")
    assert p_upi.is_actionable() is True, "UPI should be actionable"
    assert p_url.is_actionable() is True, "URL should be actionable"
    assert p_text.is_actionable() is False, "TEXT should not be actionable"
    assert p_unk.is_actionable() is False, "UNKNOWN should not be actionable"
    print("is_actionable() OK.")

    print("\n--- 3. Testing QRScanner ---")
    fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
    os.makedirs(fixtures_dir, exist_ok=True)
    test_qr_path = os.path.join(fixtures_dir, 'test_qr.png')
    
    # Create the QR code fixture if it doesn't exist
    if not os.path.exists(test_qr_path):
        print("Test fixture not found. Generating test_qr.png...")
        img = qrcode.make("https://secureqr.guardian/test")
        img.save(test_qr_path)
    
    with open(test_qr_path, "rb") as f:
        img_bytes = f.read()
        
    scanner = QRScanner()
    result = scanner.from_image_bytes(img_bytes, source="test")
    
    assert isinstance(result, SanitizedPayload), "Result is not a SanitizedPayload instance"
    assert result.data_type == DataType.URL, f"QR code decode failed. Expected URL, got {result.data_type}"
    assert result.raw_data == "https://secureqr.guardian/test", "QR code decoded text mismatch"
    print("QRScanner OK.")

    print("\nPHASE 2 VERIFIED")

if __name__ == "__main__":
    main()
