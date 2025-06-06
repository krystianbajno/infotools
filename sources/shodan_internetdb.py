#!/usr/bin/env python3

import requests
import ipaddress
import re
import socket
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Shodan InternetDB API base URL
SHODAN_INTERNETDB_BASE_URL = "https://internetdb.shodan.io"

def is_valid_ip(ip_string: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address
    
    Args:
        ip_string: String to validate as IP address
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """
    Check if a string looks like a valid domain name
    
    Args:
        domain: String to validate as domain
        
    Returns:
        True if looks like a valid domain, False otherwise
    """
    # Basic domain validation regex
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, domain.strip()) is not None

def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain names from text using regex
    
    Args:
        text: Text to search for domain names
        
    Returns:
        List of unique valid domain names found
    """
    # Domain regex pattern (simplified)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    domains = set()
    domain_matches = re.findall(domain_pattern, text)
    
    for domain in domain_matches:
        if is_valid_domain(domain):
            domains.add(domain.lower())  # Normalize to lowercase
    
    return list(domains)

def resolve_domain_to_ips(domain: str) -> List[Dict[str, str]]:
    """
    Resolve a domain name to IP addresses using DNS
    
    Args:
        domain: Domain name to resolve
        
    Returns:
        List of dictionaries with 'ip' and 'domain' keys
    """
    ips = []
    
    try:
        # Get IPv4 addresses
        try:
            ipv4_result = socket.getaddrinfo(domain, None, socket.AF_INET)
            for result in ipv4_result:
                ip = result[4][0]
                if ip not in [entry['ip'] for entry in ips]:
                    ips.append({'ip': ip, 'domain': domain, 'type': 'A'})
        except socket.gaierror:
            pass  # IPv4 resolution failed, continue
        
        # Get IPv6 addresses
        try:
            ipv6_result = socket.getaddrinfo(domain, None, socket.AF_INET6)
            for result in ipv6_result:
                ip = result[4][0]
                if ip not in [entry['ip'] for entry in ips]:
                    ips.append({'ip': ip, 'domain': domain, 'type': 'AAAA'})
        except socket.gaierror:
            pass  # IPv6 resolution failed, continue
            
    except Exception as e:
        # Return empty list if resolution completely fails
        pass
    
    return ips

def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract IP addresses from text using regex
    
    Args:
        text: Text to search for IP addresses
        
    Returns:
        List of unique valid IP addresses found
    """
    # IPv4 regex pattern
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    # IPv6 regex pattern (simplified)
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    
    ips = set()
    
    # Find IPv4 addresses
    ipv4_matches = re.findall(ipv4_pattern, text)
    for ip in ipv4_matches:
        if is_valid_ip(ip):
            ips.add(ip)
    
    # Find IPv6 addresses
    ipv6_matches = re.findall(ipv6_pattern, text)
    for ip in ipv6_matches:
        if is_valid_ip(ip):
            ips.add(ip)
    
    return list(ips)

def query_shodan_internetdb(ip: str, source_domain: str = None) -> Dict[str, Any]:
    """
    Query Shodan InternetDB for information about an IP address
    
    Args:
        ip: IP address to query
        
    Returns:
        Dictionary with IP information or error details
    """
    if not is_valid_ip(ip):
        return {"error": f"Invalid IP address: {ip}"}
    
    try:
        url = f"{SHODAN_INTERNETDB_BASE_URL}/{ip}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 404:
            result = {
                "ip": ip,
                "found": False,
                "message": "No information available for this IP"
            }
            # Add domain information if this IP was resolved from a domain
            if source_domain:
                result["resolved_from_domain"] = source_domain
            return result
        
        response.raise_for_status()
        data = response.json()
        
        # Add some metadata
        result = {
            "ip": ip,
            "found": True,
            "cpes": data.get("cpes", []),
            "hostnames": data.get("hostnames", []),
            "ports": data.get("ports", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "source": "Shodan InternetDB"
        }
        
        # Add domain information if this IP was resolved from a domain
        if source_domain:
            result["resolved_from_domain"] = source_domain
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed for {ip}: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error for {ip}: {str(e)}"}

def search_shodan_internetdb(search_term: str, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """
    Search Shodan InternetDB for IP-related information
    
    Args:
        search_term: Search term (can contain IP addresses or domain names)
        quiet: Whether to suppress print statements
        
    Returns:
        Dictionary with search results
    """
    results = {
        "search_term": search_term,
        "ips_found": 0,
        "domains_found": 0,
        "ips_queried": 0,
        "results": [],
        "errors": [],
        "dns_resolutions": []
    }
    
    ips_to_query = []  # List of tuples: (ip, source_domain)
    
    # Check if search term is a single IP address
    if is_valid_ip(search_term.strip()):
        ips_to_query.append((search_term.strip(), None))
    # Check if search term is a single domain
    elif is_valid_domain(search_term.strip()):
        domain = search_term.strip().lower()
        if not quiet:
            print(f"Resolving domain: {domain}")
        resolved_ips = resolve_domain_to_ips(domain)
        
        if resolved_ips:
            results["domains_found"] = 1
            results["dns_resolutions"].append({
                "domain": domain,
                "ips": [entry['ip'] for entry in resolved_ips],
                "types": [entry['type'] for entry in resolved_ips]
            })
            for ip_info in resolved_ips:
                ips_to_query.append((ip_info['ip'], domain))
        else:
            results["errors"].append({
                "error": f"Could not resolve domain: {domain}",
                "details": "DNS resolution failed"
            })
            return results
    else:
        # Extract both IPs and domains from search term
        direct_ips = extract_ips_from_text(search_term)
        for ip in direct_ips:
            ips_to_query.append((ip, None))
        
        domains = extract_domains_from_text(search_term)
        if domains:
            results["domains_found"] = len(domains)
            if not quiet:
                print(f"Resolving {len(domains)} domain(s)...")
            
            for domain in domains:
                resolved_ips = resolve_domain_to_ips(domain)
                if resolved_ips:
                    results["dns_resolutions"].append({
                        "domain": domain,
                        "ips": [entry['ip'] for entry in resolved_ips],
                        "types": [entry['type'] for entry in resolved_ips]
                    })
                    for ip_info in resolved_ips:
                        ips_to_query.append((ip_info['ip'], domain))
                else:
                    results["errors"].append({
                        "error": f"Could not resolve domain: {domain}",
                        "details": "DNS resolution failed"
                    })
    
    if not ips_to_query:
        results["errors"].append({
            "error": "No valid IP addresses or resolvable domains found",
            "details": f"Search term: '{search_term}'"
        })
        return results
    
    # Limit the number of IPs to query (max 10)
    ips_to_query = ips_to_query[:10]
    results["ips_found"] = len(ips_to_query)
    
    if not quiet:
        print(f"Querying Shodan InternetDB for {len(ips_to_query)} IP address(es)...")
    
    # Thread-safe progress tracking
    progress_lock = threading.Lock()
    completed_queries = 0
    
    def update_progress():
        nonlocal completed_queries
        with progress_lock:
            completed_queries += 1
            if not quiet:
                print(f"Completed {completed_queries}/{len(ips_to_query)} IP queries", end='\r')
    
    # Use ThreadPoolExecutor for concurrent requests
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all IP query tasks
        future_to_ip_info = {
            executor.submit(query_shodan_internetdb, ip, domain): (ip, domain)
            for ip, domain in ips_to_query
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_ip_info):
            ip, domain = future_to_ip_info[future]
            result = future.result()
            update_progress()
            
            if result.get("error"):
                results["errors"].append({
                    "ip": ip,
                    "domain": domain,
                    "error": result["error"]
                })
            else:
                results["results"].append(result)
                if result.get("found"):
                    results["ips_queried"] += 1
    
    if not quiet:
        print()  # New line after progress
    
    return results

def get_shodan_internetdb_summary(ip_data: Dict[str, Any]) -> str:
    """
    Generate a summary string for Shodan InternetDB data
    
    Args:
        ip_data: IP data from Shodan InternetDB
        
    Returns:
        Formatted summary string
    """
    if not ip_data.get("found"):
        return f"IP {ip_data.get('ip', 'Unknown')}: No data available"
    
    ip = ip_data.get("ip", "Unknown")
    ports = ip_data.get("ports", [])
    vulns = ip_data.get("vulns", [])
    hostnames = ip_data.get("hostnames", [])
    tags = ip_data.get("tags", [])
    
    summary_parts = [f"IP: {ip}"]
    
    if ports:
        summary_parts.append(f"Ports: {', '.join(map(str, ports[:10]))}")
        if len(ports) > 10:
            summary_parts.append(f"(+{len(ports) - 10} more)")
    
    if vulns:
        summary_parts.append(f"Vulnerabilities: {len(vulns)} CVEs")
    
    if hostnames:
        summary_parts.append(f"Hostnames: {', '.join(hostnames[:3])}")
        if len(hostnames) > 3:
            summary_parts.append(f"(+{len(hostnames) - 3} more)")
    
    if tags:
        summary_parts.append(f"Tags: {', '.join(tags[:5])}")
        if len(tags) > 5:
            summary_parts.append(f"(+{len(tags) - 5} more)")
    
    return " | ".join(summary_parts)

def test_shodan_internetdb():
    """Test function for Shodan InternetDB integration"""
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    
    print("Testing Shodan InternetDB integration...")
    
    for ip in test_ips:
        print(f"\nTesting IP: {ip}")
        result = query_shodan_internetdb(ip)
        
        if result.get("error"):
            print(f"  Error: {result['error']}")
        elif result.get("found"):
            print(f"  ✅ Found data")
            print(f"  Ports: {len(result.get('ports', []))}")
            print(f"  Vulnerabilities: {len(result.get('vulns', []))}")
            print(f"  Hostnames: {len(result.get('hostnames', []))}")
            print(f"  Tags: {len(result.get('tags', []))}")
        else:
            print(f"  ❌ No data available")

if __name__ == "__main__":
    test_shodan_internetdb() 