#!/usr/bin/env python3

import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Add sources to path
sys.path.append(str(Path(__file__).parent.parent))

from sources.malpedia import collect_malpedia_data
from sources.otx import collect_otx_data
from sources.rss import search_rss_feeds
from sources.stix import search_stix_sources
from sources.threatfox import search_threatfox
from sources.shodan_internetdb import search_shodan_internetdb
from sources.ip_geolocation import search_ip_geolocation
from sources.crtsh_subdomains import search_crtsh_subdomains

def load_env_file():
    """Load environment variables from .env file"""
    env_file = Path(__file__).parent.parent / '.env'
    if not env_file.exists():
        env_file = Path(__file__).parent.parent / '.env.example'
    
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

def get_otx_api_key():
    """Get OTX API key from environment or .env file"""
    load_env_file()
    api_key = os.environ.get('OTX_API_KEY')
    if not api_key or api_key == 'XXXXXX':
        return None
    return api_key

def search_malpedia_service(search_term: str, **kwargs) -> Dict[str, Any]:
    """Search Malpedia service wrapper"""
    try:
        references = collect_malpedia_data(search_term)
        return {
            'status': 'success',
            'source': 'malpedia',
            'results': references or [],
            'count': len(references) if references else 0,
            'error': None
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'malpedia',
            'results': [],
            'count': 0,
            'error': str(e)
        }

def search_otx_service(search_term: str, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """Search OTX service wrapper"""
    try:
        api_key = get_otx_api_key()
        if not api_key:
            return {
                'status': 'error',
                'source': 'otx',
                'results': [],
                'count': 0,
                'error': 'OTX API key not configured'
            }
        
        result = collect_otx_data(search_term, api_key, quiet=quiet)
        
        if result.get('status') == 'error':
            return {
                'status': 'error',
                'source': 'otx',
                'results': [],
                'count': 0,
                'error': result.get('error', 'Unknown OTX error')
            }
        
        pulses = result.get('pulses', [])
        return {
            'status': 'success',
            'source': 'otx',
            'results': pulses,
            'count': len(pulses),
            'error': None
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'otx',
            'results': [],
            'count': 0,
            'error': str(e)
        }

def search_rss_service(search_term: str, quiet: bool = False, reload: bool = False, **kwargs) -> Dict[str, Any]:
    """Search RSS service wrapper"""
    try:
        result = search_rss_feeds(search_term, quiet=quiet, reload=reload)
        
        return {
            'status': 'success',
            'source': 'rss',
            'results': result.get('articles', []),
            'count': result.get('articles_found', 0),
            'feeds_searched': result.get('feeds_searched', 0),
            'errors': result.get('errors', []),
            'error': None
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'rss',
            'results': [],
            'count': 0,
            'feeds_searched': 0,
            'errors': [],
            'error': str(e)
        }

def search_stix_service(search_term: str, reload: bool = False, **kwargs) -> Dict[str, Any]:
    """Search STIX/TAXII service wrapper"""
    try:
        result = search_stix_sources(search_term)
        
        return {
            'status': 'success',
            'source': 'stix',
            'results': result.get('objects', []),
            'count': result.get('objects_found', 0),
            'sources_searched': result.get('sources_searched', 0),
            'errors': result.get('errors', []),
            'error': None
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'stix',
            'results': [],
            'count': 0,
            'sources_searched': 0,
            'errors': [],
            'error': str(e)
        }

def search_threatfox_service(search_term: str, max_results: int = 0, max_days: int = 0, 
                            ioc_types: List[str] = None, malware_families: List[str] = None,
                            threat_types: List[str] = None, min_confidence: int = 0, **kwargs) -> Dict[str, Any]:
    """Search ThreatFox IOC service wrapper"""
    try:
        result = search_threatfox(
            search_term=search_term,
            max_results=max_results,
            max_days=max_days,
            ioc_types=ioc_types,
            malware_families=malware_families,
            threat_types=threat_types,
            min_confidence=min_confidence
        )
        
        return {
            'status': 'success',
            'source': 'threatfox',
            'results': result.get('iocs', []),
            'count': result.get('iocs_found', 0),
            'total_iocs_in_db': result.get('total_iocs_in_db', 0),
            'cache_age': result.get('cache_age', 'Unknown'),
            'error': result.get('error', None)
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'threatfox',
            'results': [],
            'count': 0,
            'total_iocs_in_db': 0,
            'cache_age': 'Unknown',
            'error': str(e)
        }

def search_shodan_internetdb_service(search_term: str, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """Search Shodan InternetDB service wrapper"""
    try:
        result = search_shodan_internetdb(search_term, quiet=quiet)
        
        return {
            'status': 'success',
            'source': 'shodan_internetdb',
            'results': result.get('results', []),
            'count': result.get('ips_queried', 0),
            'ips_found': result.get('ips_found', 0),
            'errors': result.get('errors', []),
            'error': None
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'shodan_internetdb',
            'results': [],
            'count': 0,
            'ips_found': 0,
            'errors': [],
            'error': str(e)
        }

def search_ip_geolocation_service(search_term: str, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """Search IP Geolocation service wrapper"""
    try:
        result = search_ip_geolocation(search_term, quiet=quiet)
        
        return {
            'status': 'success',
            'source': 'ip_geolocation',
            'results': result.get('results', []),
            'count': result.get('ips_processed', 0),
            'ips_found': result.get('ips_found', 0),
            'errors': result.get('errors', []),
            'error': None
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'ip_geolocation',
            'results': [],
            'count': 0,
            'ips_found': 0,
            'errors': [],
            'error': str(e)
        }

def search_crtsh_subdomains_service(search_term: str, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """Search crt.sh subdomain enumeration service wrapper using HTTP requests"""
    try:
        from sources.crtsh_subdomains import search_crtsh_subdomains
        
        # Search using HTTP requests and HTML parsing
        result = search_crtsh_subdomains(search_term, quiet=quiet)
        
        return {
            'status': 'success',
            'source': 'crtsh_subdomains',
            'results': result.get('subdomains', []),
            'count': result.get('total_found', 0),
            'domain_searched': result.get('domain_searched'),
            'errors': [],
            'error': result.get('error')
        }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'crtsh_subdomains',
            'results': [],
            'count': 0,
            'domain_searched': None,
            'errors': [],
            'error': str(e)
        }

# Available sources mapping
AVAILABLE_SOURCES = {
    'malpedia': {
        'name': 'Malpedia',
        'description': 'Malware research bibliography',
        'function': search_malpedia_service,
        'requires_api': False
    },
    'otx': {
        'name': 'AlienVault OTX',
        'description': 'Open Threat Exchange intelligence',
        'function': search_otx_service,
        'requires_api': True
    },
    'rss': {
        'name': 'RSS Feeds',
        'description': 'Cybersecurity news and research feeds',
        'function': search_rss_service,
        'requires_api': False
    },
    # 'stix': {
    #     'name': 'STIX/TAXII',
    #     'description': 'Structured threat intelligence feeds',
    #     'function': search_stix_service,
    #     'requires_api': False
    # },
    'threatfox': {
        'name': 'ThreatFox',
        'description': 'IOC database from abuse.ch',
        'function': search_threatfox_service,
        'requires_api': False
    },
    'shodan': {
        'name': 'Shodan InternetDB',
        'description': 'IP address intelligence (ports, vulnerabilities, hostnames)',
        'function': search_shodan_internetdb_service,
        'requires_api': False
    },
    'ipgeo': {
        'name': 'IP Geolocation & Proxy Detection',
        'description': 'IP geolocation with passive proxy/VPN detection',
        'function': search_ip_geolocation_service,
        'requires_api': False
    },
    'crtsh': {
        'name': 'crt.sh Subdomain Enumeration',
        'description': 'Certificate transparency logs for subdomain discovery',
        'function': search_crtsh_subdomains_service,
        'requires_api': False
    }
}

def search_single_source(source_name: str, search_term: str, **kwargs) -> Dict[str, Any]:
    """Search a single source"""
    if source_name not in AVAILABLE_SOURCES:
        return {
            'status': 'error',
            'source': source_name,
            'results': [],
            'count': 0,
            'error': f'Unknown source: {source_name}'
        }
    
    source_func = AVAILABLE_SOURCES[source_name]['function']
    return source_func(search_term, **kwargs)

def search_all_sources(search_term: str, sources: List[str] = None, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """
    Search across multiple sources
    
    Args:
        search_term: Term to search for
        sources: List of source names to search (None for all)
        quiet: Whether to suppress progress messages
        **kwargs: Additional arguments passed to source functions
        
    Returns:
        Dictionary with results from all sources
    """
    if sources is None:
        sources = list(AVAILABLE_SOURCES.keys())
    
    # Validate sources
    invalid_sources = [s for s in sources if s not in AVAILABLE_SOURCES]
    if invalid_sources:
        return {
            'status': 'error',
            'error': f'Invalid sources: {invalid_sources}',
            'available_sources': list(AVAILABLE_SOURCES.keys())
        }
    
    results = {
        'search_term': search_term,
        'sources_requested': sources,
        'sources_searched': [],
        'results': {}
    }
    
    # Concurrent search with improved progress tracking
    if not quiet:
        print(f"🔍 Searching {len(sources)} intelligence source{'s' if len(sources) > 1 else ''}...")
    
    # Thread-safe progress tracking
    progress_lock = threading.Lock()
    completed_sources = 0
    
    def update_progress(source_name, result_count=0):
        nonlocal completed_sources
        with progress_lock:
            completed_sources += 1
            if not quiet:
                # Show progress every source completion 
                status = f"✅ {AVAILABLE_SOURCES[source_name]['name']}"
                if result_count > 0:
                    status += f" ({result_count} results)"
                print(f"  {status}")
    
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        # Submit search tasks
        future_to_source = {
            executor.submit(search_single_source, source, search_term, **kwargs): source
            for source in sources
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                result = future.result()
                results['results'][source_name] = result
                if result['status'] == 'success':
                    results['sources_searched'].append(source_name)
                    result_count = result.get('count', len(result.get('results', [])))
                    update_progress(source_name, result_count)
                else:
                    if not quiet:
                        print(f"  ❌ {AVAILABLE_SOURCES[source_name]['name']} - {result.get('error', 'Unknown error')}")
            except Exception as e:
                results['results'][source_name] = {
                    'status': 'error',
                    'source': source_name,
                    'results': [],
                    'count': 0,
                    'error': str(e)
                }
                if not quiet:
                    print(f"  ❌ {AVAILABLE_SOURCES[source_name]['name']} - {str(e)}")
    
    if not quiet:
        successful_sources = len(results['sources_searched'])
        total_sources = len(sources)
        print(f"\n✨ Search completed: {successful_sources}/{total_sources} sources returned results")
    
    return results

def get_available_sources() -> Dict[str, Dict[str, Any]]:
    """Get information about available sources"""
    return AVAILABLE_SOURCES

def validate_source_requirements() -> Dict[str, str]:
    """Check if source requirements are met"""
    issues = {}
    
    # Check OTX API key
    if not get_otx_api_key():
        issues['otx'] = 'OTX_API_KEY not configured in .env file'
    
    return issues 