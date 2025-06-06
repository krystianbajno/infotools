import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def load_stix_sources() -> List[Dict[str, str]]:
    """Load STIX/TAXII sources from stix.txt configuration file"""
    sources = []
    stix_file = Path(__file__).parent.parent / 'stix.txt'
    
    if not stix_file.exists():
        print(f"Warning: STIX configuration file not found at {stix_file}")
        return []
    
    try:
        with open(stix_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse source line: name|url|type|api_key_required
                parts = line.split('|')
                if len(parts) < 3:
                    print(f"Warning: Invalid format in stix.txt line {line_num}: {line}")
                    continue
                
                name = parts[0].strip()
                url = parts[1].strip()
                source_type = parts[2].strip()
                api_key_required = parts[3].strip().lower() == 'true' if len(parts) > 3 else False
                
                sources.append({
                    "name": name,
                    "url": url,
                    "type": source_type,  # taxii, stix_json, misp, etc.
                    "api_key_required": api_key_required
                })
    
    except Exception as e:
        print(f"Error loading STIX sources from {stix_file}: {e}")
        return []
    
    return sources

# Load STIX sources from configuration file
STIX_SOURCES = load_stix_sources()

def query_taxii_server(url: str, collection_id: str = None, api_key: str = None, 
                      search_term: str = None, since_date: datetime = None) -> Dict[str, Any]:
    """
    Query a TAXII 2.1 server for threat intelligence data
    
    Args:
        url: TAXII server root URL
        collection_id: Specific collection to query (optional)
        api_key: API key for authentication (optional)
        search_term: Search term to filter results
        since_date: Only get data since this date
        
    Returns:
        Dictionary with TAXII query results
    """
    headers = {
        'Accept': 'application/taxii+json;version=2.1',
        'Content-Type': 'application/taxii+json;version=2.1'
    }
    
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    
    try:
        # First, discover server information
        discovery_response = requests.get(f"{url}/taxii2/", headers=headers, timeout=30)
        discovery_response.raise_for_status()
        discovery_data = discovery_response.json()
        
        api_roots = discovery_data.get('api_roots', [])
        if not api_roots:
            return {"error": "No API roots found in TAXII server"}
        
        # Use the first API root - ensure it's a full URL
        api_root = api_roots[0]
        if api_root.startswith('http'):
            api_root_url = api_root
        else:
            # Relative path, need to construct full URL
            base_url = url.rstrip('/')
            api_root_url = f"{base_url}/{api_root.lstrip('/')}"
        
        # Get collections
        collections_response = requests.get(f"{api_root_url}/collections/", headers=headers, timeout=30)
        collections_response.raise_for_status()
        collections_data = collections_response.json()
        
        collections = collections_data.get('collections', [])
        if not collections:
            return {"error": "No collections found"}
        
        results = []
        
        # Query each collection (or specific collection if provided)
        for collection in collections:
            coll_id = collection['id']
            
            if collection_id and coll_id != collection_id:
                continue
            
            # Build query parameters
            params = {}
            if since_date:
                params['added_after'] = since_date.isoformat()
            
            # Get objects from collection
            objects_url = f"{api_root_url}/collections/{coll_id}/objects/"
            objects_response = requests.get(objects_url, headers=headers, params=params, timeout=30)
            objects_response.raise_for_status()
            objects_data = objects_response.json()
            
            objects = objects_data.get('objects', [])
            
            # Filter by search term if provided
            if search_term and objects:
                search_term_lower = search_term.lower()
                filtered_objects = []
                
                for obj in objects:
                    obj_str = json.dumps(obj).lower()
                    if search_term_lower in obj_str:
                        filtered_objects.append(obj)
                
                objects = filtered_objects
            
            if objects:
                results.extend([{
                    'collection_id': coll_id,
                    'collection_title': collection.get('title', coll_id),
                    'object': obj
                } for obj in objects])
        
        return {
            "success": True,
            "server_url": url,
            "objects_found": len(results),
            "objects": results
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def query_misp_feed(url: str, api_key: str = None, search_term: str = None, 
                   since_date: datetime = None) -> Dict[str, Any]:
    """
    Query a MISP feed for threat intelligence data
    
    Args:
        url: MISP instance URL
        api_key: MISP API key
        search_term: Search term to filter results
        since_date: Only get data since this date
        
    Returns:
        Dictionary with MISP query results
    """
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    if api_key:
        headers['Authorization'] = api_key
    
    try:
        # Query events
        params = {}
        if since_date:
            params['timestamp'] = int(since_date.timestamp())
        
        if search_term:
            params['searchall'] = search_term
        
        events_url = f"{url}/events/index"
        response = requests.get(events_url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        events_data = response.json()
        events = events_data if isinstance(events_data, list) else events_data.get('response', [])
        
        return {
            "success": True,
            "server_url": url,
            "events_found": len(events),
            "events": events
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def query_stix_json_feed(url: str, search_term: str = None, since_date: datetime = None) -> Dict[str, Any]:
    """
    Query a static STIX JSON feed
    
    Args:
        url: URL to STIX JSON file
        search_term: Search term to filter results
        since_date: Only get data since this date
        
    Returns:
        Dictionary with STIX JSON results
    """
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        stix_data = response.json()
        objects = stix_data.get('objects', [])
        
        # Filter by search term if provided
        if search_term and objects:
            search_term_lower = search_term.lower()
            filtered_objects = []
            
            for obj in objects:
                obj_str = json.dumps(obj).lower()
                if search_term_lower in obj_str:
                    filtered_objects.append(obj)
            
            objects = filtered_objects
        
        # Filter by date if provided
        if since_date and objects:
            filtered_objects = []
            
            for obj in objects:
                created = obj.get('created')
                if created:
                    try:
                        obj_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        if obj_date >= since_date:
                            filtered_objects.append(obj)
                    except:
                        # Include object if date parsing fails
                        filtered_objects.append(obj)
                else:
                    # Include object if no created date
                    filtered_objects.append(obj)
            
            objects = filtered_objects
        
        return {
            "success": True,
            "feed_url": url,
            "objects_found": len(objects),
            "objects": objects
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def search_single_stix_source(source_info: Dict[str, str], search_term: str, 
                             since_date: datetime, api_key: str = None) -> Dict[str, Any]:
    """
    Search a single STIX/TAXII source for threat intelligence data
    
    Args:
        source_info: Source information dictionary
        search_term: Search term to filter results
        since_date: Only get data since this date
        api_key: API key for authentication (optional)
        
    Returns:
        Dictionary with source results
    """
    source_name = source_info["name"]
    source_url = source_info["url"]
    source_type = source_info["type"]
    
    source_result = {
        "source_name": source_name,
        "source_type": source_type,
        "success": False,
        "objects": [],
        "error": None
    }
    
    try:
        if source_type.lower() == "taxii":
            result = query_taxii_server(source_url, search_term=search_term, 
                                      since_date=since_date, api_key=api_key)
        elif source_type.lower() == "misp":
            result = query_misp_feed(source_url, api_key=api_key, search_term=search_term, 
                                   since_date=since_date)
        elif source_type.lower() == "stix_json":
            result = query_stix_json_feed(source_url, search_term=search_term, since_date=since_date)
        else:
            result = {"error": f"Unsupported source type: {source_type}"}
        
        if result.get("success"):
            source_result["success"] = True
            source_result["objects"] = result.get("objects", []) or result.get("events", [])
        else:
            source_result["error"] = result.get("error", "Unknown error")
            
    except Exception as e:
        source_result["error"] = str(e)
    
    return source_result

def search_stix_sources(search_term: str, max_sources: int = 5, max_days: int = 30, 
                       api_key: str = None) -> Dict[str, Any]:
    """
    Search STIX/TAXII sources for threat intelligence data
    
    Args:
        search_term: Term to search for
        max_sources: Maximum number of sources to search
        max_days: Maximum days to look back
        api_key: API key for authenticated sources
        
    Returns:
        Dictionary with search results
    """
    # Reload sources in case the configuration file has been updated
    global STIX_SOURCES
    STIX_SOURCES = load_stix_sources()
    
    if not STIX_SOURCES:
        return {
            "search_term": search_term,
            "sources_searched": 0,
            "objects_found": 0,
            "objects": [],
            "errors": [{"source": "Configuration", "error": "No STIX sources loaded", "details": "Check stix.txt file"}]
        }
    
    since_date = datetime.now() - timedelta(days=max_days)
    
    results = {
        "search_term": search_term,
        "sources_searched": 0,
        "objects_found": 0,
        "objects": [],
        "errors": []
    }
    
    sources_to_search = STIX_SOURCES[:max_sources] if max_sources > 0 else STIX_SOURCES
    total_sources = len(sources_to_search)
    
    print(f"Starting search of {total_sources} STIX/TAXII sources...")
    
    # Thread-safe progress tracking
    progress_lock = threading.Lock()
    completed_sources = 0
    
    def update_progress():
        nonlocal completed_sources
        with progress_lock:
            completed_sources += 1
            print(f"Completed {completed_sources}/{total_sources} sources", end='\r')
    
    # Use ThreadPoolExecutor for concurrent requests (smaller pool for STIX sources)
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all source search tasks
        future_to_source = {
            executor.submit(search_single_stix_source, source_info, search_term, since_date, api_key): source_info
            for source_info in sources_to_search
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_source):
            source_result = future.result()
            update_progress()
            
            if source_result["success"]:
                results["sources_searched"] += 1
                results["objects"].extend(source_result["objects"])
                results["objects_found"] += len(source_result["objects"])
            
            if source_result["error"]:
                results["errors"].append({
                    "source": source_result["source_name"],
                    "error": source_result["error"]
                })
    
    print()  # New line after progress
    
    return results

def get_available_stix_sources() -> List[Dict[str, str]]:
    """Get list of available STIX/TAXII sources"""
    # Reload sources to get latest configuration
    global STIX_SOURCES
    STIX_SOURCES = load_stix_sources()
    return STIX_SOURCES

def format_stix_object_summary(stix_obj: Dict[str, Any]) -> str:
    """Format a STIX object into a readable summary"""
    obj_type = stix_obj.get('type', 'unknown')
    obj_id = stix_obj.get('id', 'unknown')
    
    if obj_type == 'indicator':
        pattern = stix_obj.get('pattern', '')
        labels = ', '.join(stix_obj.get('labels', []))
        return f"Indicator: {pattern} (Labels: {labels})"
    
    elif obj_type == 'malware':
        name = stix_obj.get('name', 'Unknown')
        labels = ', '.join(stix_obj.get('labels', []))
        return f"Malware: {name} (Labels: {labels})"
    
    elif obj_type == 'threat-actor':
        name = stix_obj.get('name', 'Unknown')
        labels = ', '.join(stix_obj.get('labels', []))
        return f"Threat Actor: {name} (Labels: {labels})"
    
    elif obj_type == 'attack-pattern':
        name = stix_obj.get('name', 'Unknown')
        return f"Attack Pattern: {name}"
    
    elif obj_type == 'campaign':
        name = stix_obj.get('name', 'Unknown')
        return f"Campaign: {name}"
    
    elif obj_type == 'course-of-action':
        name = stix_obj.get('name', 'Unknown')
        return f"Course of Action: {name}"
    
    else:
        name = stix_obj.get('name', stix_obj.get('value', obj_id))
        return f"{obj_type.title()}: {name}" 