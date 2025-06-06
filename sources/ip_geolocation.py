#!/usr/bin/env python3

import requests
import ipaddress
import re
import json
import socket
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Free IP geolocation APIs (no API key required)
GEOLOCATION_APIS = [
    {
        "name": "ip-api.com",
        "url": "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile,query",
        "rate_limit": 45,  # requests per minute
        "timeout": 10
    },
    {
        "name": "ipapi.co", 
        "url": "https://ipapi.co/{ip}/json/",
        "rate_limit": 30,  # requests per minute for free tier
        "timeout": 10
    },
    {
        "name": "freegeoip.app",
        "url": "https://freegeoip.app/json/{ip}",
        "rate_limit": 15,  # requests per minute
        "timeout": 10
    }
]

# Known proxy/VPN indicators
PROXY_INDICATORS = {
    "hosting_keywords": [
        "hosting", "datacenter", "cloud", "server", "digital ocean", "amazon", 
        "google cloud", "microsoft azure", "linode", "vultr", "ovh", "hetzner"
    ],
    "proxy_keywords": [
        "proxy", "vpn", "tunnel", "anonymizer", "tor", "onion", "relay",
        "privacy", "anonymous", "hide", "mask", "shield"
    ],
    "suspicious_asn_patterns": [
        "hosting", "datacenter", "cloud", "server farm", "colocation"
    ]
}

def is_valid_ip(ip_string: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """Check if a string looks like a valid domain name"""
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, domain.strip()) is not None

def resolve_domain_to_ips(domain: str) -> List[Dict[str, str]]:
    """Resolve a domain name to IP addresses using DNS"""
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
            pass
        
        # Get IPv6 addresses
        try:
            ipv6_result = socket.getaddrinfo(domain, None, socket.AF_INET6)
            for result in ipv6_result:
                ip = result[4][0]
                if ip not in [entry['ip'] for entry in ips]:
                    ips.append({'ip': ip, 'domain': domain, 'type': 'AAAA'})
        except socket.gaierror:
            pass
    except Exception as e:
        pass
    return ips

def extract_domains_from_text(text: str) -> List[str]:
    """Extract domain names from text using regex"""
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = set()
    domain_matches = re.findall(domain_pattern, text)
    for domain in domain_matches:
        if is_valid_domain(domain):
            domains.add(domain.lower())
    return list(domains)

def extract_ips_from_text(text: str) -> List[str]:
    """Extract IP addresses from text using regex"""
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

def detect_proxy_indicators(geo_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect proxy/VPN indicators from geolocation data
    Inspired by check_proxy.py methodology
    """
    indicators = {
        "is_proxy": False,
        "is_hosting": False,
        "is_mobile": False,
        "proxy_score": 0,
        "indicators_found": [],
        "risk_level": "low"
    }
    
    # Extract fields for analysis
    isp = str(geo_data.get('isp', '')).lower()
    org = str(geo_data.get('org', '')).lower() 
    asn = str(geo_data.get('as', '')).lower()
    
    # Check for explicit proxy flag (ip-api.com provides this)
    if geo_data.get('proxy', False):
        indicators["is_proxy"] = True
        indicators["proxy_score"] += 50
        indicators["indicators_found"].append("Explicit proxy flag")
    
    # Check for hosting flag (ip-api.com provides this)  
    if geo_data.get('hosting', False):
        indicators["is_hosting"] = True
        indicators["proxy_score"] += 30
        indicators["indicators_found"].append("Hosting provider flag")
    
    # Check for mobile flag
    if geo_data.get('mobile', False):
        indicators["is_mobile"] = True
        indicators["proxy_score"] -= 10  # Mobile IPs are less likely to be proxies
        indicators["indicators_found"].append("Mobile connection")
    
    # Check ISP/Org for hosting keywords
    for keyword in PROXY_INDICATORS["hosting_keywords"]:
        if keyword in isp or keyword in org:
            indicators["is_hosting"] = True
            indicators["proxy_score"] += 20
            indicators["indicators_found"].append(f"Hosting keyword: {keyword}")
    
    # Check for proxy keywords
    for keyword in PROXY_INDICATORS["proxy_keywords"]:
        if keyword in isp or keyword in org:
            indicators["is_proxy"] = True
            indicators["proxy_score"] += 40
            indicators["indicators_found"].append(f"Proxy keyword: {keyword}")
    
    # Check ASN patterns
    for pattern in PROXY_INDICATORS["suspicious_asn_patterns"]:
        if pattern in asn:
            indicators["proxy_score"] += 15
            indicators["indicators_found"].append(f"Suspicious ASN: {pattern}")
    
    # Determine overall proxy likelihood
    if indicators["proxy_score"] >= 50:
        indicators["is_proxy"] = True
        indicators["risk_level"] = "high"
    elif indicators["proxy_score"] >= 30:
        indicators["risk_level"] = "medium"
    elif indicators["proxy_score"] >= 15:
        indicators["risk_level"] = "low"
    
    return indicators

def query_ip_geolocation(ip: str, api_index: int = 0, source_domain: str = None) -> Dict[str, Any]:
    """
    Query IP geolocation from available APIs with fallback
    """
    if not is_valid_ip(ip):
        return {"error": f"Invalid IP address: {ip}"}
    
    # Try APIs in order until one works
    for i in range(len(GEOLOCATION_APIS)):
        api_idx = (api_index + i) % len(GEOLOCATION_APIS)
        api = GEOLOCATION_APIS[api_idx]
        
        try:
            url = api["url"].format(ip=ip)
            response = requests.get(url, timeout=api["timeout"])
            
            if response.status_code == 200:
                data = response.json()
                
                # Handle different API response formats
                if api["name"] == "ip-api.com":
                    if data.get("status") == "fail":
                        continue  # Try next API
                    
                    # Normalize ip-api.com response
                    result = {
                        "ip": ip,
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False),
                        "mobile": data.get("mobile", False),
                        "source": api["name"]
                    }
                    
                elif api["name"] == "ipapi.co":
                    if data.get("error"):
                        continue  # Try next API
                    
                    # Normalize ipapi.co response
                    result = {
                        "ip": ip,
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "zip": data.get("postal"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("org"),
                        "org": data.get("org"),
                        "as": data.get("asn"),
                        "source": api["name"]
                    }
                    
                elif api["name"] == "freegeoip.app":
                    # Normalize freegeoip.app response
                    result = {
                        "ip": ip,
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code"),
                        "region": data.get("region_name"),
                        "city": data.get("city"),
                        "zip": data.get("zip_code"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "timezone": data.get("time_zone"),
                        "isp": data.get("org"),
                        "org": data.get("org"),
                        "source": api["name"]
                    }
                
                # Add proxy detection
                proxy_info = detect_proxy_indicators(result)
                result.update(proxy_info)
                
                # Add domain information if this IP was resolved from a domain
                if source_domain:
                    result["resolved_from_domain"] = source_domain
                
                return result
                
        except requests.exceptions.RequestException as e:
            continue  # Try next API
        except Exception as e:
            continue  # Try next API
    
    return {"error": f"All geolocation APIs failed for {ip}"}

def search_ip_geolocation(search_term: str, quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """
    Search IP geolocation for IPs found in search term
    """
    results = {
        "search_term": search_term,
        "ips_found": 0,
        "domains_found": 0,
        "ips_processed": 0,
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
    
    # Limit the number of IPs to process (max 10)
    ips_to_query = ips_to_query[:10]
    results["ips_found"] = len(ips_to_query)
    
    if not quiet:
        print(f"Getting geolocation for {len(ips_to_query)} IP address(es)...")
    
    # Thread-safe progress tracking
    progress_lock = threading.Lock()
    completed_queries = 0
    
    def update_progress():
        nonlocal completed_queries
        with progress_lock:
            completed_queries += 1
            if not quiet:
                print(f"Completed {completed_queries}/{len(ips_to_query)} IP queries", end='\r')
    
    # Use ThreadPoolExecutor for concurrent requests (rate-limited)
    with ThreadPoolExecutor(max_workers=3) as executor:  # Limited workers for rate limiting
        # Submit all IP query tasks with staggered start times
        future_to_ip_info = {}
        for i, (ip, domain) in enumerate(ips_to_query):
            # Stagger requests to respect rate limits
            api_index = i % len(GEOLOCATION_APIS)
            future = executor.submit(query_ip_geolocation, ip, api_index, domain)
            future_to_ip_info[future] = (ip, domain)
            if i > 0:
                time.sleep(1)  # Rate limiting delay
        
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
                results["ips_processed"] += 1
    
    if not quiet:
        print()  # New line after progress
    
    return results

def get_ip_geolocation_summary(geo_data: Dict[str, Any]) -> str:
    """Generate a summary string for IP geolocation data"""
    if geo_data.get("error"):
        return f"IP {geo_data.get('ip', 'Unknown')}: {geo_data['error']}"
    
    ip = geo_data.get("ip", "Unknown")
    country = geo_data.get("country", "Unknown")
    city = geo_data.get("city", "Unknown")
    isp = geo_data.get("isp", "Unknown")
    
    summary_parts = [f"IP: {ip}"]
    
    if city and country:
        summary_parts.append(f"Location: {city}, {country}")
    elif country:
        summary_parts.append(f"Country: {country}")
    
    if isp:
        summary_parts.append(f"ISP: {isp}")
    
    # Add proxy information
    if geo_data.get("is_proxy"):
        summary_parts.append("🚨 PROXY DETECTED")
    elif geo_data.get("is_hosting"):
        summary_parts.append("🏢 Hosting Provider")
    elif geo_data.get("is_mobile"):
        summary_parts.append("📱 Mobile")
    
    risk_level = geo_data.get("risk_level", "low")
    if risk_level != "low":
        summary_parts.append(f"Risk: {risk_level.upper()}")
    
    return " | ".join(summary_parts)

def test_ip_geolocation():
    """Test function for IP geolocation integration"""
    test_ips = ["8.8.8.8", "1.1.1.1", "185.220.102.8"]  # Last one is a Tor exit node
    
    print("Testing IP Geolocation integration...")
    
    for ip in test_ips:
        print(f"\nTesting IP: {ip}")
        result = query_ip_geolocation(ip)
        
        if result.get("error"):
            print(f"  Error: {result['error']}")
        else:
            print(f"  ✅ Location: {result.get('city', 'Unknown')}, {result.get('country', 'Unknown')}")
            print(f"  ISP: {result.get('isp', 'Unknown')}")
            print(f"  Proxy: {'Yes' if result.get('is_proxy') else 'No'}")
            print(f"  Hosting: {'Yes' if result.get('is_hosting') else 'No'}")
            print(f"  Risk Level: {result.get('risk_level', 'low')}")
            if result.get('indicators_found'):
                print(f"  Indicators: {', '.join(result['indicators_found'])}")

if __name__ == "__main__":
    test_ip_geolocation() 