"""
Pydantic models for scanner output. This is the contract between the scanner
and all downstream modules. Never modify field names without updating all consumers.
"""

import uuid
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

class DataType(str, Enum):
    UPI = "UPI"
    URL = "URL"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"

class SanitizedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_data: str
    data_type: DataType
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    input_source: str = Field(default="unknown")

    def is_actionable(self) -> bool:
        return self.data_type in (DataType.UPI, DataType.URL)
