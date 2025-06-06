#!/usr/bin/env python3

from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class Entry:
    """Entry model for subdomain enumeration results"""
    
    subdomain: str
    domain: str
    certificate_id: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    common_name: Optional[str] = None
    subject_alternative_names: Optional[list] = None
    
    def __post_init__(self):
        """Ensure subdomain is properly formatted"""
        if self.subdomain and not self.subdomain.startswith('*.'):
            # Normalize subdomain format
            self.subdomain = self.subdomain.lower().strip()
        
        if self.domain:
            self.domain = self.domain.lower().strip()
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'subdomain': self.subdomain,
            'domain': self.domain,
            'certificate_id': self.certificate_id,
            'issuer': self.issuer,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'common_name': self.common_name,
            'subject_alternative_names': self.subject_alternative_names
        } 