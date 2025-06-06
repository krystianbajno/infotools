import requests
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import time
import gzip
import shutil
import zipfile
import io

class ThreatFoxClient:
    """Client for ThreatFox threat intelligence platform"""
    
    def __init__(self, cache_dir: str = None):
        self.base_url = "https://threatfox.abuse.ch"
        self.cache_dir = Path(cache_dir or Path(__file__).parent.parent / 'data' / 'threatfox')
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / 'threatfox_full.json'
        self.cache_age_hours = 6  # Refresh cache every 6 hours
        
    def _is_cache_fresh(self) -> bool:
        """Check if the cached data is still fresh"""
        if not self.cache_file.exists():
            return False
        
        cache_age = time.time() - self.cache_file.stat().st_mtime
        return cache_age < (self.cache_age_hours * 3600)
    
    def _download_full_dump(self) -> bool:
        """Download the full ThreatFox database"""
        print("Downloading ThreatFox full database...")
        
        try:
            # Download the full JSON dump
            url = f"{self.base_url}/export/json/full/"
            headers = {
                'User-Agent': 'ThreatFox-Client/1.0 (Threat Intelligence Search Tool)',
                'Accept': 'application/zip, application/json, */*'
            }
            
            response = requests.get(url, headers=headers, timeout=120)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            content_bytes = response.content
            
            print(f"Response content-type: {content_type}, size: {len(content_bytes)} bytes")
            
            # Handle different content types
            if 'zip' in content_type or content_bytes.startswith(b'PK'):
                # It's a ZIP file
                print("Extracting ZIP archive...")
                
                try:
                    # Use BytesIO to treat the content as a file-like object
                    zip_buffer = io.BytesIO(content_bytes)
                    
                    with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
                        # List files in the ZIP
                        file_list = zip_file.namelist()
                        print(f"Files in ZIP: {file_list}")
                        
                        # Look for JSON file (usually named 'full.json' or similar)
                        json_file = None
                        for filename in file_list:
                            if filename.endswith('.json'):
                                json_file = filename
                                break
                        
                        if not json_file:
                            print("No JSON file found in ZIP archive")
                            return False
                        
                        # Extract and read the JSON file
                        with zip_file.open(json_file) as f:
                            content = f.read().decode('utf-8')
                
                except zipfile.BadZipFile as e:
                    print(f"Bad ZIP file: {e}")
                    return False
                    
            elif content_bytes.startswith(b'\x1f\x8b'):
                # It's gzipped
                print("Extracting gzip content...")
                content = gzip.decompress(content_bytes).decode('utf-8')
                
            else:
                # Assume it's plain text/JSON
                print("Processing as plain text...")
                content = response.text
            
            # Validate JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                print(f"Content preview: {content[:500]}")
                return False
            
            # Save to cache
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            print(f"Successfully downloaded {len(data)} ThreatFox IOC entries")
            return True
            
        except Exception as e:
            print(f"Error downloading ThreatFox data: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _load_cached_data(self) -> Dict[str, Any]:
        """Load data from cache"""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading cached ThreatFox data: {e}")
            return {}
    
    def get_iocs(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get IOCs from ThreatFox, using cache when possible"""
        if force_refresh or not self._is_cache_fresh():
            if not self._download_full_dump():
                # If download fails, try to use cached data
                if self.cache_file.exists():
                    print("Download failed, using cached data...")
                    return self._load_cached_data()
                else:
                    return {}
        
        return self._load_cached_data()
    
    def search_iocs(self, search_term: str, max_results: int = 0, 
                   since_date: datetime = None, ioc_types: List[str] = None,
                   malware_families: List[str] = None, threat_types: List[str] = None,
                   min_confidence: int = 0) -> Dict[str, Any]:
        """
        Search ThreatFox IOCs
        
        Args:
            search_term: Term to search for in IOC values, malware names, tags, etc.
            max_results: Maximum number of results to return
            since_date: Only return IOCs seen since this date
            ioc_types: Filter by IOC types (ip:port, domain, url, etc.)
            malware_families: Filter by malware families
            threat_types: Filter by threat types (botnet_cc, payload_delivery, etc.)
            min_confidence: Minimum confidence level (0-100)
            
        Returns:
            Dictionary with search results
        """
        iocs_data = self.get_iocs()
        
        if not iocs_data:
            return {
                "search_term": search_term,
                "iocs_found": 0,
                "iocs": [],
                "error": "No ThreatFox data available"
            }
        
        search_term_lower = search_term.lower() if search_term else ""
        matched_iocs = []
        
        # Search through all IOCs
        for ioc_id, ioc_entries in iocs_data.items():
            for ioc_entry in ioc_entries:
                # Apply filters
                if since_date:
                    first_seen = ioc_entry.get('first_seen_utc')
                    if first_seen:
                        try:
                            ioc_date = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
                            if ioc_date < since_date:
                                continue
                        except:
                            pass  # Skip date filtering if parsing fails
                
                if ioc_types and ioc_entry.get('ioc_type') not in ioc_types:
                    continue
                
                if malware_families:
                    malware = ioc_entry.get('malware', '').lower()
                    malware_printable = ioc_entry.get('malware_printable', '').lower()
                    if not any(family.lower() in malware or family.lower() in malware_printable 
                             for family in malware_families):
                        continue
                
                if threat_types and ioc_entry.get('threat_type') not in threat_types:
                    continue
                
                if ioc_entry.get('confidence_level', 0) < min_confidence:
                    continue
                
                # Search in various fields
                if search_term_lower:
                    searchable_text = " ".join([
                        str(ioc_entry.get('ioc_value', '')),
                        str(ioc_entry.get('malware', '')),
                        str(ioc_entry.get('malware_printable', '')),
                        str(ioc_entry.get('malware_alias', '') or ''),
                        str(ioc_entry.get('tags', '')),
                        str(ioc_entry.get('reporter', '')),
                        str(ioc_entry.get('threat_type', '')),
                        str(ioc_entry.get('ioc_type', ''))
                    ]).lower()
                    
                    if search_term_lower not in searchable_text:
                        continue
                
                # Add IOC ID and entry to result
                result_entry = {
                    'ioc_id': ioc_id,
                    **ioc_entry
                }
                matched_iocs.append(result_entry)
                
                if max_results > 0 and len(matched_iocs) >= max_results:
                    break
            
            if max_results > 0 and len(matched_iocs) >= max_results:
                break
        
        # Sort by first_seen_utc (newest first)
        matched_iocs.sort(key=lambda x: x.get('first_seen_utc', ''), reverse=True)
        
        return {
            "search_term": search_term,
            "iocs_found": len(matched_iocs),
            "iocs": matched_iocs,
            "total_iocs_in_db": len(iocs_data),
            "cache_age": self._get_cache_age()
        }
    
    def _get_cache_age(self) -> str:
        """Get human-readable cache age"""
        if not self.cache_file.exists():
            return "No cache"
        
        cache_age_seconds = time.time() - self.cache_file.stat().st_mtime
        if cache_age_seconds < 3600:
            return f"{int(cache_age_seconds / 60)} minutes ago"
        else:
            return f"{int(cache_age_seconds / 3600)} hours ago"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the ThreatFox database"""
        iocs_data = self.get_iocs()
        
        if not iocs_data:
            return {"error": "No data available"}
        
        stats = {
            "total_ioc_entries": len(iocs_data),
            "total_ioc_records": sum(len(entries) for entries in iocs_data.values()),
            "cache_age": self._get_cache_age(),
            "ioc_types": {},
            "malware_families": {},
            "threat_types": {},
            "reporters": {}
        }
        
        # Analyze data
        for ioc_entries in iocs_data.values():
            for entry in ioc_entries:
                # Count IOC types
                ioc_type = entry.get('ioc_type', 'unknown')
                stats["ioc_types"][ioc_type] = stats["ioc_types"].get(ioc_type, 0) + 1
                
                # Count malware families
                malware = entry.get('malware_printable', entry.get('malware', 'unknown'))
                stats["malware_families"][malware] = stats["malware_families"].get(malware, 0) + 1
                
                # Count threat types
                threat_type = entry.get('threat_type', 'unknown')
                stats["threat_types"][threat_type] = stats["threat_types"].get(threat_type, 0) + 1
                
                # Count reporters
                reporter = entry.get('reporter', 'unknown')
                stats["reporters"][reporter] = stats["reporters"].get(reporter, 0) + 1
        
        # Sort by frequency (top 10)
        for category in ["ioc_types", "malware_families", "threat_types", "reporters"]:
            stats[category] = dict(sorted(stats[category].items(), 
                                        key=lambda x: x[1], reverse=True)[:10])
        
        return stats

# Global ThreatFox client instance
_threatfox_client = None

def get_threatfox_client() -> ThreatFoxClient:
    """Get or create ThreatFox client instance"""
    global _threatfox_client
    if _threatfox_client is None:
        _threatfox_client = ThreatFoxClient()
    return _threatfox_client

def search_threatfox(search_term: str, max_results: int = 0, max_days: int = 0,
                    ioc_types: List[str] = None, malware_families: List[str] = None,
                    threat_types: List[str] = None, min_confidence: int = 0) -> Dict[str, Any]:
    """
    Search ThreatFox IOCs
    
    Args:
        search_term: Term to search for
        max_results: Maximum number of results
        max_days: Look back this many days
        ioc_types: Filter by IOC types
        malware_families: Filter by malware families  
        threat_types: Filter by threat types
        min_confidence: Minimum confidence level
        
    Returns:
        Search results dictionary
    """
    client = get_threatfox_client()
    since_date = datetime.now() - timedelta(days=max_days) if max_days > 0 else None
    
    try:
        results = client.search_iocs(
            search_term=search_term,
            max_results=max_results,
            since_date=since_date,
            ioc_types=ioc_types,
            malware_families=malware_families,
            threat_types=threat_types,
            min_confidence=min_confidence
        )
        return results
    except Exception as e:
        return {
            "search_term": search_term,
            "iocs_found": 0,
            "iocs": [],
            "error": str(e)
        }

def get_threatfox_stats() -> Dict[str, Any]:
    """Get ThreatFox database statistics"""
    client = get_threatfox_client()
    return client.get_stats()

def refresh_threatfox_data() -> bool:
    """Force refresh of ThreatFox data"""
    client = get_threatfox_client()
    return client._download_full_dump() 