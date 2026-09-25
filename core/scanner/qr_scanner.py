"""
QR code scanner. Wraps OpenCV and pyzbar. Always returns SanitizedPayload.
Never raises exceptions. Failures return DataType.UNKNOWN.
"""

import cv2
import numpy as np
from pyzbar import pyzbar

from core.scanner.sanitizer import sanitize
from core.scanner.payload_models import SanitizedPayload, DataType
from utils.logger import get_logger

logger = get_logger(__name__)

class QRScanner:
    def from_image_bytes(self, data: bytes, source: str = "file") -> SanitizedPayload:
        try:
            # Decode bytes to numpy array
            nparr = np.frombuffer(data, np.uint8)
            # Decode with OpenCV
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if frame is None:
                logger.warning("Failed to decode image bytes into a valid frame.", extra={"source": source})
                return SanitizedPayload(raw_data="", data_type=DataType.UNKNOWN, input_source=source)
                
            return self.from_camera_frame(frame, source=source)
            
        except Exception as e:
            logger.error(f"Exception while decoding image bytes: {str(e)}", extra={"source": source}, exc_info=True)
            return SanitizedPayload(raw_data="", data_type=DataType.UNKNOWN, input_source=source)

    def from_camera_frame(self, frame: np.ndarray, source: str = "camera") -> SanitizedPayload:
        try:
            if frame is None:
                return SanitizedPayload(raw_data="", data_type=DataType.UNKNOWN, input_source=source)

            # Use pyzbar.decode() to extract QR data
            decoded_objects = pyzbar.decode(frame)
            
            if not decoded_objects:
                return SanitizedPayload(raw_data="", data_type=DataType.UNKNOWN, input_source=source)
                
            # Extract the string payload from the first QR code detected
            raw_string = decoded_objects[0].data.decode('utf-8', errors='replace')
            
            # Pass decoded string to sanitize()
            return sanitize(raw_string, source=source)
            
        except Exception as e:
            logger.error(f"Exception while processing camera frame: {str(e)}", extra={"source": source}, exc_info=True)
            return SanitizedPayload(raw_data="", data_type=DataType.UNKNOWN, input_source=source)
