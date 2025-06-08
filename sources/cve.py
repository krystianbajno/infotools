#!/usr/bin/env python3

import json
import os
import requests
import lzma
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import logging
import re
from datetime import datetime, timedelta

# Setup logging
logger = logging.getLogger(__name__)

class CVEDatabase:
    """CVE Database handler for NIST NVD data"""
    
    def __init__(self, cache_dir: Optional[str] = None):
        """Initialize CVE database handler
        
        Args:
            cache_dir: Directory to store cached CVE data (default: data/cve/)
        """
        if cache_dir is None:
            cache_dir = Path(__file__).parent.parent / "data" / "cve"
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_file = self.cache_dir / "cve_database.json"
        self.raw_file = self.cache_dir / "CVE-all.json.xz"
        
        # CVE data URL
        self.download_url = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"
        
        # Cache expiry (7 days)
        self.cache_expiry_days = 7
        
        # Load or initialize database
        self._cve_data = None
        self._alias_map = None
        
    def _is_cache_expired(self) -> bool:
        """Check if cache is expired"""
        if not self.db_file.exists():
            return True
            
        try:
            mod_time = datetime.fromtimestamp(self.db_file.stat().st_mtime)
            expiry_time = datetime.now() - timedelta(days=self.cache_expiry_days)
            return mod_time < expiry_time
        except:
            return True
    
    def _download_cve_database(self) -> bool:
        """Download the CVE database from NIST NVD"""
        try:
            logger.info(f"Downloading CVE database from {self.download_url}")
            
            # Download with progress
            response = requests.get(self.download_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(self.raw_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\rDownloading CVE database: {progress:.1f}%", end="", flush=True)
            
            print()  # New line after progress
            logger.info("CVE database download completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download CVE database: {e}")
            return False
    
    def _extract_and_process_database(self) -> bool:
        """Extract and process the downloaded CVE database"""
        try:
            logger.info("Processing CVE database...")
            
            # Extract and parse the compressed JSON
            with lzma.open(self.raw_file, 'rt', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            # Process CVE entries to extract aliases and build searchable database
            processed_data = {}
            alias_map = {}  # Maps aliases to CVE IDs
            
            cve_vulnerabilities = raw_data.get('CVE_Items', [])
            if not cve_vulnerabilities:
                # Try newer format
                cve_vulnerabilities = raw_data.get('vulnerabilities', [])
            if not cve_vulnerabilities:
                # Try fkie-cad format
                cve_vulnerabilities = raw_data.get('cve_items', [])
            
            total_cves = len(cve_vulnerabilities)
            processed_count = 0
            
            for item in cve_vulnerabilities:
                try:
                    # Extract CVE ID
                    cve_id = None
                    cve_data = {}
                    
                    # Handle different data formats
                    if 'id' in item:
                        # New fkie-cad format
                        cve_id = item.get('id')
                        
                        # Extract description
                        descriptions = item.get('descriptions', [])
                        if descriptions:
                            # Find English description
                            for desc in descriptions:
                                if desc.get('lang') == 'en':
                                    cve_data['description'] = desc.get('value', '')
                                    break
                            else:
                                # Fallback to first description
                                cve_data['description'] = descriptions[0].get('value', '')
                        
                        # Extract references
                        references = item.get('references', [])
                        
                    elif 'cve' in item:
                        # Old NIST format
                        cve_info = item['cve']
                        cve_id = cve_info.get('CVE_data_meta', {}).get('ID') or cve_info.get('id')
                        
                        # Extract description
                        descriptions = cve_info.get('description', {}).get('description_data', [])
                        if descriptions:
                            cve_data['description'] = descriptions[0].get('value', '')
                        else:
                            # Try newer format
                            descriptions = cve_info.get('descriptions', [])
                            if descriptions:
                                cve_data['description'] = descriptions[0].get('value', '')
                        
                        # Extract references for aliases
                        references = cve_info.get('references', {}).get('reference_data', [])
                        if not references:
                            references = cve_info.get('references', [])
                        
                    elif 'CVE_data_meta' in item:
                        # Very old format
                        cve_id = item['CVE_data_meta'].get('ID')
                        cve_data['description'] = item.get('description', {}).get('description_data', [{}])[0].get('value', '')
                        references = item.get('references', {}).get('reference_data', [])
                    
                    if not cve_id:
                        continue
                    
                    # Simple aliases - only CVE ID
                    aliases = set([cve_id])
                    
                    # Store CVE data
                    cve_data['cve_id'] = cve_id
                    cve_data['aliases'] = list(aliases)
                    cve_data['references'] = references
                    
                    # Add to main database (avoid duplicates)
                    if cve_id not in processed_data:
                        processed_data[cve_id] = cve_data
                    else:
                        # Merge aliases if CVE already exists
                        existing_aliases = set(processed_data[cve_id].get('aliases', []))
                        new_aliases = set(aliases)
                        processed_data[cve_id]['aliases'] = list(existing_aliases.union(new_aliases))
                    
                    # Add to alias mapping
                    for alias in aliases:
                        if alias not in alias_map:
                            alias_map[alias] = []
                        alias_map[alias].append(cve_id)
                    
                    # Also map CVE ID to itself for consistency
                    alias_map[cve_id] = [cve_id]
                    
                    processed_count += 1
                    if processed_count % 1000 == 0:
                        progress = (processed_count / total_cves) * 100
                        print(f"\rProcessing CVEs: {progress:.1f}% ({processed_count}/{total_cves})", end="", flush=True)
                        
                except Exception as e:
                    logger.warning(f"Error processing CVE item: {e}")
                    continue
            
            print()  # New line after progress
            
            # Save processed database
            database = {
                'cve_data': processed_data,
                'alias_map': alias_map,
                'processed_at': datetime.now().isoformat(),
                'total_cves': len(processed_data),
                'total_aliases': len(alias_map)
            }
            
            with open(self.db_file, 'w') as f:
                json.dump(database, f, indent=2)
            
            logger.info(f"Processed {len(processed_data)} CVEs with {len(alias_map)} total aliases")
            return True
            
        except Exception as e:
            logger.error(f"Failed to process CVE database: {e}")
            return False
    

    
    def _load_database(self) -> bool:
        """Load the processed CVE database"""
        try:
            if not self.db_file.exists():
                return False
                
            with open(self.db_file, 'r') as f:
                database = json.load(f)
            
            self._cve_data = database.get('cve_data', {})
            self._alias_map = database.get('alias_map', {})
            
            logger.info(f"Loaded CVE database with {len(self._cve_data)} CVEs and {len(self._alias_map)} aliases")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
            return False
    
    def ensure_database_ready(self, force_update: bool = False) -> bool:
        """Ensure CVE database is ready for queries
        
        Args:
            force_update: Force download even if cache is not expired
            
        Returns:
            True if database is ready, False otherwise
        """
        # Check if we need to update
        needs_update = force_update or self._is_cache_expired()
        
        if needs_update:
            logger.info("CVE database needs updating")
            
            # Download and process
            if not self._download_cve_database():
                logger.warning("Failed to download CVE database, trying to use existing cache")
                return self._load_database()
            
            if not self._extract_and_process_database():
                logger.warning("Failed to process CVE database, trying to use existing cache")
                return self._load_database()
        
        # Load the database
        return self._load_database()
    
    def get_cve_aliases(self, cve_id: str) -> List[str]:
        """Get aliases for a given CVE ID
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2017-0144')
            
        Returns:
            List of aliases for the CVE
        """
        if not self._cve_data:
            if not self.ensure_database_ready():
                return []
        
        cve_data = self._cve_data.get(cve_id, {})
        return cve_data.get('aliases', [])
    
    def search_by_alias(self, alias: str) -> List[Dict[str, Any]]:
        """Search for CVEs by alias
        
        Args:
            alias: Alias to search for (e.g., 'ETERNALBLUE', 'MS17-010')
            
        Returns:
            List of CVE records matching the alias
        """
        if not self._alias_map:
            if not self.ensure_database_ready():
                return []
        
        # Case-insensitive search
        alias_upper = alias.upper()
        cve_ids = self._alias_map.get(alias_upper, [])
        
        results = []
        for cve_id in cve_ids:
            cve_data = self._cve_data.get(cve_id, {})
            if cve_data:
                results.append(cve_data)
        
        return results
    
    def search_cve_database(self, search_term: str) -> List[Dict[str, Any]]:
        """Search CVE database for a term
        
        Args:
            search_term: Term to search for (CVE ID, alias, or keyword)
            
        Returns:
            List of matching CVE records
        """
        if not self._cve_data or not self._alias_map:
            if not self.ensure_database_ready():
                return []
        
        results = []
        search_term_upper = search_term.upper()
        
        # Direct CVE ID lookup
        if search_term_upper.startswith('CVE-'):
            cve_data = self._cve_data.get(search_term_upper, {})
            if cve_data:
                results.append(cve_data)
        
        # Alias lookup
        alias_results = self.search_by_alias(search_term)
        results.extend(alias_results)
        
        # Keyword search in descriptions (limited to prevent overwhelming results)
        if len(results) < 10:  # Only do keyword search if we don't have many results
            for cve_id, cve_data in list(self._cve_data.items())[:1000]:  # Limit search scope
                description = cve_data.get('description', '').upper()
                if search_term_upper in description and cve_data not in results:
                    results.append(cve_data)
                    if len(results) >= 20:  # Limit results
                        break
        
        return results


def search_cve(search_term: str, reload: bool = False, **kwargs) -> Dict[str, Any]:
    """Search CVE database
    
    Args:
        search_term: Term to search for
        reload: Force database reload
        **kwargs: Additional arguments
        
    Returns:
        Dictionary with search results
    """
    try:
        cve_db = CVEDatabase()
        
        # Ensure database is ready
        if not cve_db.ensure_database_ready(force_update=reload):
            return {
                'cves': [],
                'aliases_found': [],
                'total_found': 0,
                'search_term': search_term,
                'error': 'Failed to load CVE database'
            }
        
        # Search the database
        results = cve_db.search_cve_database(search_term)
        
        # Extract unique aliases from results
        all_aliases = set()
        for result in results:
            all_aliases.update(result.get('aliases', []))
            all_aliases.add(result.get('cve_id', ''))
        
        # Remove the search term itself from aliases
        all_aliases.discard(search_term.upper())
        
        return {
            'cves': results,
            'aliases_found': sorted(list(all_aliases)),
            'total_found': len(results),
            'search_term': search_term,
            'error': None
        }
        
    except Exception as e:
        logger.error(f"CVE search error: {e}")
        return {
            'cves': [],
            'aliases_found': [],
            'total_found': 0,
            'search_term': search_term,
            'error': str(e)
        }


def get_cve_aliases(cve_id: str) -> List[str]:
    """Get aliases for a specific CVE ID
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2017-0144')
        
    Returns:
        List of aliases for the CVE
    """
    try:
        cve_db = CVEDatabase()
        
        if not cve_db.ensure_database_ready():
            logger.error("Failed to load CVE database")
            return []
        
        return cve_db.get_cve_aliases(cve_id.upper())
        
    except Exception as e:
        logger.error(f"Error getting CVE aliases: {e}")
        return []


# Example usage and testing
if __name__ == "__main__":
    # Test the CVE database functionality
    print("Testing CVE database...")
    
    # Test search
    results = search_cve("CVE-2017-0144")
    print(f"CVE-2017-0144 search results: {len(results['cves'])} found")
    print(f"Aliases found: {results['aliases_found']}")
    
    # Test alias lookup
    aliases = get_cve_aliases("CVE-2017-0144")
    print(f"CVE-2017-0144 aliases: {aliases}")
    
    # Test reverse lookup
    results = search_cve("ETERNALBLUE")
    print(f"ETERNALBLUE search results: {len(results['cves'])} found")
    
    results = search_cve("MS17-010") 
    print(f"MS17-010 search results: {len(results['cves'])} found") 