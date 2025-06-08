#!/usr/bin/env python3

import asyncio
import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import time
from urllib.parse import urlparse, quote
import httpx
from bs4 import BeautifulSoup
import logging

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CrtshSubdomainCollector:
    """
    Lightweight crt.sh subdomain collector using HTTP requests
    Based on Subduer's approach but without browser automation
    """
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.base_url = "https://crt.sh"
        self.session = None
        
    async def collect_subdomains(self, domain: str, max_results: int = 100) -> Dict[str, Any]:
        """
        Collect subdomains from crt.sh using HTTP requests
        
        Args:
            domain: Target domain to search for subdomains
            max_results: Maximum number of results to return
            
        Returns:
            Dictionary containing subdomains and metadata
        """
        try:
            # Validate and clean domain
            clean_domain = self._extract_domain(domain)
            if not clean_domain:
                return {
                    'subdomains': [],
                    'total_found': 0,
                    'domain_searched': domain,
                    'error': f'Invalid domain: {domain}'
                }
            
            logger.info(f"Starting crt.sh subdomain enumeration for: {clean_domain}")
            
            # Create HTTP client
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                self.session = client
                
                # Try multiple approaches to get subdomains
                subdomains_with_metadata = {}
                
                # Approach 1: JSON API (preferred - more reliable)
                json_subdomains_metadata = await self._collect_from_json_api(clean_domain)
                subdomains_with_metadata.update(json_subdomains_metadata)
                
                # Approach 2: HTML search (fallback) - only if JSON found nothing
                if len(json_subdomains_metadata) == 0:
                    html_subdomains = await self._collect_from_html(clean_domain)
                    # Convert HTML results to metadata format
                    for subdomain in html_subdomains:
                        subdomains_with_metadata[subdomain] = {
                            'certificate_id': 'N/A',
                            'issuer': 'crt.sh (HTML)',
                            'not_before': 'N/A',
                            'not_after': 'N/A',
                            'common_name': subdomain,
                            'subject_alternative_names': []
                        }
                
                # Process and deduplicate results
                processed_subdomains = self._process_subdomains_with_metadata(subdomains_with_metadata, clean_domain, max_results)
                
                return {
                    'subdomains': processed_subdomains,
                    'total_found': len(processed_subdomains),
                    'domain_searched': clean_domain,
                    'error': None
                }
                    
        except Exception as e:
            logger.error(f"Error collecting subdomains from crt.sh: {str(e)}")
            return {
                'subdomains': [],
                'total_found': 0,
                'domain_searched': domain,
                'error': str(e)
            }
    
    async def _collect_from_html(self, domain: str) -> Set[str]:
        """Collect subdomains from HTML search page"""
        subdomains = set()
        
        try:
            logger.info(f"HTML search for domain: {domain}")
            
            # Search for subdomains using wildcard
            search_url = f"{self.base_url}/?q=%.{domain}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = await self.session.get(search_url, headers=headers)
            response.raise_for_status()
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract subdomains from table
            page_subdomains = self._extract_subdomains_from_html(soup, domain)
            subdomains.update(page_subdomains)
            
            if page_subdomains:
                logger.info(f"Found {len(page_subdomains)} subdomains in HTML")
            else:
                logger.warning(f"No subdomains found in HTML")
                
        except Exception as e:
            logger.error(f"HTML search failed: {str(e)}")
        
        return subdomains
    
    async def _collect_from_json_api(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Collect subdomains with certificate metadata from JSON API endpoint"""
        subdomains_with_metadata = {}
        
        try:
            logger.info(f"Trying JSON API for domain: {domain}")
            
            # Try JSON API endpoint
            json_url = f"{self.base_url}/?q=%.{domain}&output=json"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json,text/plain,*/*'
            }
            
            response = await self.session.get(json_url, headers=headers)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        for entry in data:
                            if isinstance(entry, dict):
                                # Extract certificate metadata
                                cert_id = str(entry.get('id', 'N/A'))
                                issuer = entry.get('issuer_name', 'Unknown')
                                not_before = entry.get('not_before', 'N/A')
                                not_after = entry.get('not_after', 'N/A')
                                
                                # Extract subdomains from name_value field (Subject Alternative Names)
                                subdomains_from_entry = set()
                                if 'name_value' in entry:
                                    name_values = entry['name_value'].split('\n')
                                    for name in name_values:
                                        name = name.strip()
                                        if name and domain in name:
                                            cleaned = self._clean_subdomain(name, domain)
                                            if cleaned:
                                                subdomains_from_entry.add(cleaned)
                                
                                # Also extract from common_name field
                                if 'common_name' in entry:
                                    common_name = entry['common_name'].strip()
                                    if common_name and domain in common_name:
                                        cleaned = self._clean_subdomain(common_name, domain)
                                        if cleaned:
                                            subdomains_from_entry.add(cleaned)
                                
                                # Store metadata for each subdomain found in this certificate
                                for subdomain in subdomains_from_entry:
                                    # Use the most recent certificate data if subdomain appears in multiple certs
                                    if subdomain not in subdomains_with_metadata or self._is_more_recent_cert(
                                        not_before, subdomains_with_metadata[subdomain].get('not_before', 'N/A')):
                                        subdomains_with_metadata[subdomain] = {
                                            'certificate_id': cert_id,
                                            'issuer': issuer,
                                            'not_before': not_before,
                                            'not_after': not_after,
                                            'common_name': entry.get('common_name', subdomain),
                                            'subject_alternative_names': [n.strip() for n in entry.get('name_value', '').split('\n') if n.strip()]
                                        }
                    
                    logger.info(f"Found {len(subdomains_with_metadata)} subdomains from JSON API")
                    
                except json.JSONDecodeError:
                    logger.warning("JSON API response was not valid JSON")
                    
        except Exception as e:
            logger.warning(f"JSON API request failed: {str(e)}")
        
        return subdomains_with_metadata
    
    def _is_more_recent_cert(self, date1: str, date2: str) -> bool:
        """Compare certificate dates to determine which is more recent"""
        try:
            if date1 == 'N/A' or date2 == 'N/A':
                return date1 != 'N/A'
            
            # Simple string comparison works for ISO date format (YYYY-MM-DD)
            return date1 > date2
        except:
            return False
    
    def _extract_subdomains_from_html(self, soup: BeautifulSoup, domain: str) -> Set[str]:
        """Extract subdomains from BeautifulSoup parsed HTML"""
        subdomains = set()
        
        try:
            # Look for the main table with certificate data
            main_table = soup.find('table')
            
            if main_table:
                rows = main_table.find_all('tr')[1:]  # Skip header row
                
                for row in rows:
                    cells = row.find_all('td')
                    
                    if len(cells) >= 5:  # crt.sh typically has: ID, Logged At, Not Before, Not After, Common Name, Matching Identities
                        # The Common Name is usually in the 5th column (index 4)
                        # The Matching Identities is usually in the 6th column (index 5)
                        
                        # Extract from Common Name column (index 4)
                        if len(cells) > 4:
                            common_name_cell = cells[4]
                            common_name_text = common_name_cell.get_text(strip=True)
                            if common_name_text:
                                potential_subdomains = self._extract_domains_from_text(common_name_text, domain)
                                subdomains.update(potential_subdomains)
                        
                        # Extract from Matching Identities column (index 5) if it exists
                        if len(cells) > 5:
                            matching_identities_cell = cells[5]
                            matching_text = matching_identities_cell.get_text(strip=True)
                            if matching_text:
                                # Split by common separators in this field
                                identity_parts = re.split(r'[\n\r\t\|]+', matching_text)
                                for part in identity_parts:
                                    part = part.strip()
                                    if part:
                                        potential_subdomains = self._extract_domains_from_text(part, domain)
                                        subdomains.update(potential_subdomains)
            
            # Also look for any <td> tags that directly contain domains
            all_cells = soup.find_all('td')
            for cell in all_cells:
                cell_text = cell.get_text(strip=True)
                # Only process cells that look like they contain domains
                if cell_text and '.' in cell_text and domain in cell_text:
                    # Check if this looks like a domain (not a date, ID, etc.)
                    if not re.match(r'^\d+$', cell_text) and not re.match(r'\d{4}-\d{2}-\d{2}', cell_text):
                        potential_subdomains = self._extract_domains_from_text(cell_text, domain)
                        subdomains.update(potential_subdomains)
            
        except Exception as e:
            logger.error(f"Error parsing HTML: {str(e)}")
        
        return subdomains
    
    def _extract_domains_from_text(self, text: str, domain: str) -> Set[str]:
        """Extract domain names from text content"""
        subdomains = set()
        
        if not text:
            return subdomains
        
        # First, check if the text itself is a valid subdomain
        cleaned = self._clean_subdomain(text, domain)
        if cleaned:
            subdomains.add(cleaned)
            return subdomains  # If we found a direct match, return it
        
        # Split text by common separators and newlines
        parts = re.split(r'[\s,;\n\r\t\|]+', text)
        
        for part in parts:
            part = part.strip()
            if part and '.' in part:  # Only process parts that could be domains
                cleaned = self._clean_subdomain(part, domain)
                if cleaned:
                    subdomains.add(cleaned)
        
        return subdomains
    
    def _extract_domains_with_regex(self, text: str, domain: str) -> Set[str]:
        """Extract domains using regex patterns"""
        subdomains = set()
        
        if not text:
            return subdomains
        
        # Escape domain for regex
        escaped_domain = re.escape(domain)
        
        # More specific patterns for crt.sh output
        patterns = [
            # Exact subdomain pattern (most precise)
            r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + escaped_domain + r'\b',
            # Wildcard pattern
            r'\*\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + escaped_domain + r'\b',
            # Simple pattern for edge cases
            r'[a-zA-Z0-9\-\.]+\.' + escaped_domain + r'\b'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                full_match = match.group(0)
                
                # Clean up the match
                if full_match.startswith('http://') or full_match.startswith('https://'):
                    full_match = urlparse(full_match).netloc
                
                # Remove wildcard prefix if present
                if full_match.startswith('*.'):
                    full_match = full_match[2:]
                
                cleaned = self._clean_subdomain(full_match, domain)
                if cleaned:
                    subdomains.add(cleaned)
        
        return subdomains
    
    def _clean_subdomain(self, subdomain: str, domain: str) -> Optional[str]:
        """Clean and validate subdomain"""
        if not subdomain:
            return None
            
        # Remove extra whitespace and convert to lowercase
        cleaned = subdomain.strip().lower()
        
        # Remove protocol if present
        if cleaned.startswith(('http://', 'https://')):
            cleaned = urlparse(cleaned).netloc
        
        # Remove asterisks and other wildcards at the beginning
        cleaned = cleaned.replace('*.', '')
        if cleaned.startswith('*'):
            cleaned = cleaned[1:]
        
        # Remove leading dots
        cleaned = cleaned.lstrip('.')
        
        # Remove any duplicate domain suffixes (common parsing issue)
        if domain in cleaned:
            # Find the last occurrence of the domain
            last_index = cleaned.rfind('.' + domain)
            if last_index != -1:
                # Keep everything up to and including the last occurrence
                cleaned = cleaned[:last_index + len(domain) + 1]
            elif cleaned.endswith(domain) and not cleaned.endswith('.' + domain):
                # Handle case where domain appears at the end without a dot
                if len(cleaned) > len(domain):
                    before_domain = cleaned[:-len(domain)]
                    if before_domain.endswith('.'):
                        cleaned = before_domain + domain
        
        # Ensure it ends with the target domain
        if not cleaned.endswith('.' + domain) and cleaned != domain:
            return None
        
        # Remove any remaining artifacts or duplicated parts
        if cleaned.count(domain) > 1:
            # Keep only the last valid occurrence
            parts = cleaned.split('.')
            valid_parts = []
            domain_parts = domain.split('.')
            
            # Find where the target domain starts
            for i in range(len(parts) - len(domain_parts) + 1):
                if parts[i:i+len(domain_parts)] == domain_parts:
                    valid_parts = parts[:i+len(domain_parts)]
                    break
            
            if valid_parts:
                cleaned = '.'.join(valid_parts)
        
        # Basic validation
        if not self._is_valid_subdomain(cleaned):
            return None
            
        return cleaned
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain:
            return False
            
        # Check length
        if len(subdomain) > 253:
            return False
        
        # Basic regex validation
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(pattern, subdomain):
            return False
            
        # Each label should be <= 63 characters
        labels = subdomain.split('.')
        for label in labels:
            if len(label) > 63:
                return False
            
        return True
    
    def _extract_domain(self, search_term: str) -> Optional[str]:
        """Extract domain from search term"""
        if not search_term:
            return None
            
        # Remove protocol if present
        if '://' in search_term:
            search_term = urlparse(search_term).netloc or search_term.split('://', 1)[1]
        
        # Remove path and query parameters
        domain = search_term.split('/')[0].split('?')[0].lower().strip()
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return None
            
        return domain
    
    def _process_subdomains_with_metadata(self, subdomains_metadata: Dict[str, Dict[str, Any]], domain: str, max_results: int) -> List[Dict[str, Any]]:
        """Process and convert subdomains with metadata to dictionary objects"""
        entries = []
        
        # Sort subdomains for consistent output (by subdomain name)
        sorted_subdomains = sorted(subdomains_metadata.keys())
        
        # Limit results
        if max_results > 0:
            sorted_subdomains = sorted_subdomains[:max_results]
        
        for subdomain in sorted_subdomains:
            metadata = subdomains_metadata[subdomain]
            entry = {
                'subdomain': subdomain,
                'domain': domain,
                'certificate_id': metadata.get('certificate_id', 'N/A'),
                'issuer': metadata.get('issuer', 'crt.sh'),
                'not_before': metadata.get('not_before', 'N/A'),
                'not_after': metadata.get('not_after', 'N/A'),
                'common_name': metadata.get('common_name', subdomain),
                'subject_alternative_names': metadata.get('subject_alternative_names', [])
            }
            entries.append(entry)
        
        return entries


def search_crtsh_subdomains(search_term: str, quiet: bool = False, max_results: int = 100, **kwargs) -> Dict[str, Any]:
    """
    Main function to search for subdomains using crt.sh
    
    Args:
        search_term: Domain to search for subdomains
        quiet: Whether to suppress logging output
        max_results: Maximum number of results to return
        
    Returns:
        Dictionary containing subdomain results and metadata
    """
    
    async def run_collection():
        # Configure logging based on quiet mode
        if quiet:
            # Suppress all logging for this specific logger and httpx
            logging.getLogger('sources.crtsh_subdomains').disabled = True
            logging.getLogger('httpx').disabled = True
            logger.disabled = True
        
        collector = CrtshSubdomainCollector()
        return await collector.collect_subdomains(search_term, max_results)
    
    # Handle existing event loop
    try:
        loop = asyncio.get_running_loop()
        # If we're in an existing loop, we can't use asyncio.run()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, run_collection())
            return future.result()
    except RuntimeError:
        # No existing event loop, safe to use asyncio.run()
        return asyncio.run(run_collection())


if __name__ == "__main__":
    # Test the collector
    if len(sys.argv) != 2:
        print("Usage: python crtsh_subdomains.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"Testing crt.sh subdomain collection for: {domain}")
    
    result = search_crtsh_subdomains(domain, max_results=10)
    
    print(f"\nResults:")
    print(f"Domain searched: {result['domain_searched']}")
    print(f"Total found: {result['total_found']}")
    print(f"Error: {result['error']}")
    print(f"\nSubdomains:")
    for entry in result['subdomains']:
        print(f"  {entry['subdomain']}") 