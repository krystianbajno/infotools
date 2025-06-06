#!/usr/bin/env python3

import requests
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Any, List

def load_stix_sources() -> List[Dict[str, str]]:
    """Load STIX/TAXII sources from stix.txt configuration file"""
    sources = []
    stix_file = Path(__file__).parent / 'stix.txt'
    
    if not stix_file.exists():
        print(f"❌ STIX configuration file not found at {stix_file}")
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
                    print(f"⚠️  Invalid format in stix.txt line {line_num}: {line}")
                    continue
                
                name = parts[0].strip()
                url = parts[1].strip()
                source_type = parts[2].strip()
                api_key_required = parts[3].strip().lower() == 'true' if len(parts) > 3 else False
                
                sources.append({
                    "name": name,
                    "url": url,
                    "type": source_type,
                    "api_key_required": api_key_required
                })
    
    except Exception as e:
        print(f"❌ Error loading STIX sources from {stix_file}: {e}")
        return []
    
    return sources

def test_taxii_server(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Test TAXII server connectivity and basic functionality"""
    headers = {
        'Accept': 'application/taxii+json;version=2.1',
        'Content-Type': 'application/taxii+json;version=2.1'
    }
    
    try:
        start_time = time.time()
        
        # Test discovery endpoint
        discovery_response = requests.get(f"{url}/taxii2/", headers=headers, timeout=timeout)
        discovery_response.raise_for_status()
        
        # Validate JSON response
        discovery_data = discovery_response.json()
        
        response_time = time.time() - start_time
        
        # Basic validation
        if 'api_roots' not in discovery_data:
            return {
                "status": "invalid",
                "error": "No api_roots in discovery response",
                "response_time": response_time,
                "http_status": discovery_response.status_code
            }
        
        api_roots = discovery_data.get('api_roots', [])
        if not api_roots:
            return {
                "status": "invalid", 
                "error": "Empty api_roots list",
                "response_time": response_time,
                "http_status": discovery_response.status_code
            }
        
        return {
            "status": "active",
            "response_time": response_time,
            "http_status": discovery_response.status_code,
            "api_roots_count": len(api_roots)
        }
        
    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "connection_error", "error": "Connection failed"}
    except requests.exceptions.HTTPError as e:
        return {"status": "http_error", "error": f"HTTP {e.response.status_code}", "http_status": e.response.status_code}
    except json.JSONDecodeError:
        return {"status": "invalid_json", "error": "Invalid JSON response"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def test_misp_feed(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Test MISP feed connectivity"""
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    try:
        start_time = time.time()
        
        # Test MISP server info endpoint
        response = requests.get(f"{url}/servers/getVersion", headers=headers, timeout=timeout)
        response.raise_for_status()
        
        response_time = time.time() - start_time
        
        return {
            "status": "active",
            "response_time": response_time,
            "http_status": response.status_code
        }
        
    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "connection_error", "error": "Connection failed"}
    except requests.exceptions.HTTPError as e:
        return {"status": "http_error", "error": f"HTTP {e.response.status_code}", "http_status": e.response.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def test_stix_json_feed(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Test STIX JSON feed connectivity"""
    headers = {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; STIX Testing Bot)'
    }
    
    try:
        start_time = time.time()
        
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        response_time = time.time() - start_time
        
        # Try to parse as JSON
        try:
            data = response.json()
            # Basic STIX validation
            if isinstance(data, dict) and 'objects' in data:
                return {
                    "status": "active",
                    "response_time": response_time,
                    "http_status": response.status_code,
                    "objects_count": len(data.get('objects', []))
                }
            elif isinstance(data, list):
                return {
                    "status": "active", 
                    "response_time": response_time,
                    "http_status": response.status_code,
                    "objects_count": len(data)
                }
            else:
                return {
                    "status": "invalid",
                    "error": "Not a valid STIX JSON format",
                    "response_time": response_time,
                    "http_status": response.status_code
                }
        except json.JSONDecodeError:
            return {
                "status": "invalid_json",
                "error": "Invalid JSON response",
                "response_time": response_time,
                "http_status": response.status_code
            }
        
    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "connection_error", "error": "Connection failed"}
    except requests.exceptions.HTTPError as e:
        return {"status": "http_error", "error": f"HTTP {e.response.status_code}", "http_status": e.response.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def test_single_stix_source(source: Dict[str, str], timeout: int = 5) -> Dict[str, Any]:
    """Test a single STIX source"""
    name = source["name"]
    url = source["url"]
    source_type = source["type"]
    api_key_required = source["api_key_required"]
    
    print(f"Testing: {name:<50} ... ", end="", flush=True)
    
    result = {"name": name, "url": url, "type": source_type}
    
    # Skip sources that require API keys for now
    if api_key_required:
        print("🔑 SKIP (requires API key)")
        result.update({
            "status": "skipped",
            "error": "Requires API key"
        })
        return result
    
    # Test based on source type
    if source_type == "taxii":
        test_result = test_taxii_server(url, timeout)
    elif source_type == "misp":
        test_result = test_misp_feed(url, timeout)
    elif source_type == "stix_json":
        test_result = test_stix_json_feed(url, timeout)
    else:
        print("❓ UNKNOWN TYPE")
        result.update({
            "status": "unknown_type",
            "error": f"Unknown source type: {source_type}"
        })
        return result
    
    result.update(test_result)
    
    # Print result
    if test_result["status"] == "active":
        response_time = test_result.get("response_time", 0)
        print(f"✅ OK ({response_time:.2f}s)")
    elif test_result["status"] == "timeout":
        print("⏰ TIMEOUT")
    elif test_result["status"] == "connection_error":
        print("🔌 CONNECTION ERROR")
    elif test_result["status"] == "http_error":
        http_status = test_result.get("http_status", "Unknown")
        print(f"❌ HTTP {http_status}")
    elif test_result["status"] == "invalid_json":
        print("❓ INVALID JSON")
    elif test_result["status"] == "invalid":
        print("❌ INVALID RESPONSE")
    else:
        print(f"❌ ERROR: {test_result.get('error', 'Unknown')}")
    
    return result

def test_all_stix_sources(timeout: int = 5, max_workers: int = 10):
    """Test all STIX sources concurrently"""
    sources = load_stix_sources()
    
    if not sources:
        print("❌ No STIX sources to test")
        return
    
    print(f"📊 Testing {len(sources)} STIX sources (timeout: {timeout}s)")
    print("=" * 80)
    
    active_sources = []
    inactive_sources = []
    skipped_sources = []
    
    # Test sources concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_source = {
            executor.submit(test_single_stix_source, source, timeout): source 
            for source in sources
        }
        
        for future in as_completed(future_to_source):
            result = future.result()
            
            if result["status"] == "active":
                active_sources.append(result)
            elif result["status"] == "skipped":
                skipped_sources.append(result)
            else:
                inactive_sources.append(result)
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 STIX SOURCE TEST SUMMARY")
    print("=" * 80)
    
    total_tested = len(sources) - len(skipped_sources)
    active_count = len(active_sources)
    inactive_count = len(inactive_sources)
    skipped_count = len(skipped_sources)
    
    if total_tested > 0:
        success_rate = (active_count / total_tested) * 100
        print(f"✅ Active sources:        {active_count}")
        print(f"❌ Inactive sources:      {inactive_count}")
        print(f"🔑 Skipped sources:       {skipped_count}")
        print(f"📈 Success rate:          {success_rate:.1f}%")
        
        if active_sources:
            avg_response_time = sum(s.get("response_time", 0) for s in active_sources) / len(active_sources)
            print(f"⏱️  Average response time: {avg_response_time:.2f}s")
    else:
        print("⚠️  No sources were tested (all require API keys)")
    
    # Detailed inactive source breakdown
    if inactive_sources:
        print(f"\n❌ Inactive Sources ({len(inactive_sources)}):")
        error_types = {}
        for source in inactive_sources:
            error_type = source["status"]
            if error_type not in error_types:
                error_types[error_type] = []
            error_types[error_type].append(source)
        
        for error_type, sources_list in error_types.items():
            print(f"  {error_type}: {len(sources_list)} sources")
        
        print("\nDetailed errors:")
        for source in inactive_sources:
            name = source["name"]
            error = source.get("error", "Unknown error")
            print(f"  - {name}: {error}")
    
    # Generate active sources file
    if active_sources:
        print(f"\n💾 Generating active_stix_sources.txt with {len(active_sources)} working sources...")
        
        with open("active_stix_sources.txt", "w") as f:
            f.write("# Active STIX/TAXII Sources (generated automatically)\n")
            f.write("# Format: name|url|type|api_key_required\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Success rate: {success_rate:.1f}% ({active_count}/{total_tested} sources)\n\n")
            
            # Group by source type
            by_type = {}
            for source in active_sources:
                source_type = source["type"]
                if source_type not in by_type:
                    by_type[source_type] = []
                by_type[source_type].append(source)
            
            for source_type, sources_list in sorted(by_type.items()):
                f.write(f"# {source_type.upper()} Sources ({len(sources_list)})\n")
                for source in sorted(sources_list, key=lambda x: x["name"]):
                    f.write(f"{source['name']}|{source['url']}|{source['type']}|false\n")
                f.write("\n")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test STIX/TAXII sources connectivity")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--workers", type=int, default=10, help="Max concurrent workers (default: 10)")
    
    args = parser.parse_args()
    
    test_all_stix_sources(timeout=args.timeout, max_workers=args.workers) 