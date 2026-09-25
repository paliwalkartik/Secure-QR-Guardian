"""
Tests for QR scanner module and payload sanitizer.
"""
import pytest
from unittest.mock import patch, MagicMock
import numpy as np
from core.scanner.sanitizer import sanitize
from core.scanner.qr_scanner import QRScanner
from core.scanner.payload_models import DataType

@pytest.fixture
def mock_scanner():
    return QRScanner()

def test_sanitize_valid_url():
    """Test sanitizer correctly identifies and cleans a URL payload."""
    raw = " https://example.com/pay  "  # scheme must be lowercase for regex match
    result = sanitize(raw)
    assert result.data_type == DataType.URL
    assert result.raw_data == "https://example.com/pay"

def test_sanitize_valid_upi():
    """Test sanitizer correctly identifies a valid UPI string."""
    raw = "upi://pay?pa=test@upi&pn=Test"
    result = sanitize(raw)
    assert result.data_type == DataType.UPI
    assert result.raw_data == "upi://pay?pa=test@upi&pn=Test"

def test_sanitize_plain_text():
    """Test sanitizer falls back to TEXT for random content."""
    raw = "Hello World"
    result = sanitize(raw)
    assert result.data_type == DataType.TEXT
    assert result.raw_data == "Hello World"

@patch("core.scanner.qr_scanner.pyzbar.decode")
def test_qrscanner_from_camera_frame(mock_decode, mock_scanner):
    """Test QRScanner extracts payload correctly from an image frame."""
    mock_obj = MagicMock()
    mock_obj.data = b"https://test.com"
    mock_decode.return_value = [mock_obj]
    
    frame = np.zeros((100, 100, 3), dtype=np.uint8)
    result = mock_scanner.from_camera_frame(frame)
    assert result.data_type == DataType.URL
    assert result.raw_data == "https://test.com"

@patch("core.scanner.qr_scanner.cv2.imdecode")
@patch.object(QRScanner, "from_camera_frame")
def test_qrscanner_from_image_bytes(mock_from_frame, mock_imdecode, mock_scanner):
    """Test QRScanner successfully translates bytes into a frame for pyzbar."""
    mock_imdecode.return_value = np.zeros((100, 100, 3), dtype=np.uint8)
    mock_payload = MagicMock()
    mock_payload.data_type = DataType.URL
    mock_from_frame.return_value = mock_payload
    
    result = mock_scanner.from_image_bytes(b"fakebytes")
    assert result.data_type == DataType.URL
    mock_from_frame.assert_called_once()
