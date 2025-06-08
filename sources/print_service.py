#!/usr/bin/env python3

from typing import List, Dict, Any
from datetime import datetime
from sources.stix import format_stix_object_summary

def format_malpedia_result(ref: Dict[str, Any], index: int) -> str:
    """Format a Malpedia reference for display"""
    output = []
    output.append(f"[{index}] (MALPEDIA)")
    output.append(f"  Title: {ref.get('title', 'No title available')}")
    
    if ref.get('author'):
        output.append(f"  Author(s): {ref['author']}")
    
    if ref.get('year'):
        output.append(f"  Year: {ref['year']}")
    elif ref.get('date'):
        output.append(f"  Date: {ref['date']}")
    
    if ref.get('url'):
        output.append(f"  URL: {ref['url']}")
    
    return "\n".join(output)

def format_otx_result(pulse: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format an OTX pulse for display"""
    output = []
    output.append(f"[{index}] (OTX)")
    output.append(f"  Name: {pulse.get('name', 'No name available')}")
    output.append(f"  ID: {pulse.get('id', 'N/A')}")
    output.append(f"  URL: https://otx.alienvault.com/pulse/{pulse.get('id', '')}")
    
    if pulse.get('author_name'):
        output.append(f"  Author: {pulse['author_name']}")
    
    if pulse.get('created'):
        output.append(f"  Created: {pulse['created']}")
    
    if pulse.get('description'):
        output.append(f"  Description: {pulse['description']}")
    
    if pulse.get('tags'):
        tags = ", ".join(pulse['tags'])
        output.append(f"  Tags: {tags}")
    
    if verbose and pulse.get('indicators'):
        indicators = pulse['indicators']
        output.append(f"  Indicators ({len(indicators)}):")
        for indicator in indicators:  # Show first 5 indicators
            ioc_type = indicator.get('type', 'unknown')
            ioc_value = indicator.get('indicator', 'N/A')
            output.append(f"    - {ioc_type}: {ioc_value}")

    elif pulse.get('indicators'):
        output.append(f"  Indicators: {len(pulse['indicators'])} available")
    
    return "\n".join(output)

def format_rss_result(article: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format an RSS article for display"""
    output = []
    output.append(f"[{index}] (RSS)")
    output.append(f"  Title: {article['title']}")
    output.append(f"  Feed: {article['feed_name']} ({article['feed_category']})")
    
    if article['published']:
        pub_date = article['published'][:19].replace('T', ' ')  # Format datetime
        output.append(f"  Published: {pub_date}")
    
    output.append(f"  URL: {article['link']}")
    
    if article['summary']:
        output.append(f"  Summary: {article['summary']}")
    
    if verbose and article['content'] and article['content'] != article['summary']:
        output.append(f"  Content: {article['content']}")
    
    return "\n".join(output)

def format_stix_result(stix_obj: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format a STIX object for display"""
    output = []
    output.append(f"[{index}] (STIX)")
    
    # Handle both collection results and direct objects
    if 'object' in stix_obj:
        obj = stix_obj['object']
        collection_title = stix_obj.get('collection_title', 'Unknown Collection')
        output.append(f"  Collection: {collection_title}")
    else:
        obj = stix_obj
    
    # Use our formatting function for the object
    summary = format_stix_object_summary(obj)
    output.append(f"  {summary}")
    
    # Add object details
    if obj.get('id'):
        output.append(f"  ID: {obj['id']}")
    
    if obj.get('created'):
        output.append(f"  Created: {obj['created']}")
    
    if obj.get('modified'):
        output.append(f"  Modified: {obj['modified']}")
    
    # Type-specific details
    obj_type = obj.get('type', 'unknown')
    
    if obj_type == 'indicator' and obj.get('pattern'):
        output.append(f"  Pattern: {obj['pattern']}")
        if obj.get('labels'):
            output.append(f"  Labels: {', '.join(obj['labels'])}")
    
    elif obj_type in ['malware', 'threat-actor', 'campaign'] and obj.get('description'):
        desc = obj.get('description', '')
        if desc:
            output.append(f"  Description: {desc}")
    
    elif obj_type == 'attack-pattern':
        if obj.get('description'):
            desc = obj['description']
            output.append(f"  Description: {desc}")
        if obj.get('kill_chain_phases'):
            phases = [f"{phase.get('kill_chain_name', 'unknown')}: {phase.get('phase_name', 'unknown')}" 
                     for phase in obj['kill_chain_phases']]
            output.append(f"  Kill Chain: {', '.join(phases)}")
    
    if verbose and obj.get('external_references'):
        output.append("  External References:")
        for ref in obj['external_references']:  # Show first 3 refs
            if ref.get('url'):
                output.append(f"    - {ref.get('source_name', 'Unknown')}: {ref['url']}")
    
    return "\n".join(output)

def format_threatfox_result(ioc: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format a ThreatFox IOC for display"""
    output = []
    output.append(f"[{index}] (THREATFOX)")
    output.append(f"  IOC: {ioc.get('ioc_value', 'N/A')}")
    output.append(f"  Type: {ioc.get('ioc_type', 'unknown')}")
    output.append(f"  Threat: {ioc.get('threat_type', 'unknown')}")
    
    malware_name = ioc.get('malware_printable', ioc.get('malware', 'unknown'))
    output.append(f"  Malware: {malware_name}")
    
    if ioc.get('malware_alias'):
        output.append(f"  Aliases: {ioc['malware_alias']}")
    
    if ioc.get('first_seen_utc'):
        output.append(f"  First Seen: {ioc['first_seen_utc']}")
    
    if ioc.get('last_seen_utc'):
        output.append(f"  Last Seen: {ioc['last_seen_utc']}")
    
    confidence = ioc.get('confidence_level', 0)
    output.append(f"  Confidence: {confidence}%")
    
    if ioc.get('reporter'):
        output.append(f"  Reporter: {ioc['reporter']}")
    
    if ioc.get('tags'):
        output.append(f"  Tags: {ioc['tags']}")
    
    if verbose and ioc.get('reference'):
        output.append(f"  Reference: {ioc['reference']}")
    
    if verbose and ioc.get('ioc_id'):
        output.append(f"  ThreatFox ID: {ioc['ioc_id']}")
    
    return "\n".join(output)

def format_shodan_internetdb_result(ip_data: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format a Shodan InternetDB result for display"""
    output = []
    output.append(f"[{index}] (SHODAN INTERNETDB)")
    
    if not ip_data.get("found"):
        output.append(f"  IP: {ip_data.get('ip', 'Unknown')}")
        output.append(f"  Status: No data available")
        return "\n".join(output)
    
    ip = ip_data.get("ip", "Unknown")
    ports = ip_data.get("ports", [])
    vulns = ip_data.get("vulns", [])
    hostnames = ip_data.get("hostnames", [])
    tags = ip_data.get("tags", [])
    cpes = ip_data.get("cpes", [])
    
    output.append(f"  IP: {ip}")
    
    # Show if this IP was resolved from a domain
    if ip_data.get("resolved_from_domain"):
        output.append(f"  🌐 Resolved from domain: {ip_data['resolved_from_domain']}")
    
    if ports:
            output.append(f"  Open Ports: {', '.join(map(str, ports))}")
    
    if vulns:
            output.append(f"  Vulnerabilities: {', '.join(vulns)}")
    
    if hostnames:
            output.append(f"  Hostnames: {', '.join(hostnames)}")
    
    if tags:
            output.append(f"  Tags: {', '.join(tags)}")
    
    if verbose and cpes:
        output.append(f"  CPEs ({len(cpes)}):")
        for cpe in cpes: 
            output.append(f"    - {cpe}")
    elif cpes:
        output.append(f"  CPEs: {len(cpes)} available")
    
    return "\n".join(output)

def format_crtsh_subdomain_result(subdomain_data: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format a crt.sh subdomain result for display"""
    output = []
    output.append(f"[{index}] (CRT.SH SUBDOMAINS)")
    output.append(f"  Subdomain: {subdomain_data.get('subdomain', 'Unknown')}")
    output.append(f"  Domain: {subdomain_data.get('domain', 'Unknown')}")
    
    if subdomain_data.get('certificate_id'):
        output.append(f"  Certificate ID: {subdomain_data['certificate_id']}")
    
    if subdomain_data.get('issuer'):
        output.append(f"  Issuer: {subdomain_data['issuer']}")
    
    if subdomain_data.get('not_before'):
        output.append(f"  Valid From: {subdomain_data['not_before']}")
    
    if subdomain_data.get('not_after'):
        output.append(f"  Valid Until: {subdomain_data['not_after']}")
    
    if subdomain_data.get('common_name'):
        output.append(f"  Common Name: {subdomain_data['common_name']}")
    
    if verbose and subdomain_data.get('subject_alternative_names'):
        san_list = subdomain_data['subject_alternative_names']
        output.append(f"  Subject Alternative Names ({len(san_list)}):")
        for san in san_list:  # Show first 5 SANs
            output.append(f"    - {san}")
    elif subdomain_data.get('subject_alternative_names'):
        san_count = len(subdomain_data['subject_alternative_names'])
        output.append(f"  Subject Alternative Names: {san_count} available")
    
    return "\n".join(output)




def format_ip_geolocation_result(geo_data: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format an IP geolocation result for display"""
    output = []
    output.append(f"[{index}] (IP GEOLOCATION)")
    
    if geo_data.get("error"):
        output.append(f"  IP: {geo_data.get('ip', 'Unknown')}")
        output.append(f"  Error: {geo_data['error']}")
        return "\n".join(output)
    
    ip = geo_data.get("ip", "Unknown")
    country = geo_data.get("country", "Unknown")
    city = geo_data.get("city", "Unknown")
    region = geo_data.get("region", "Unknown")
    isp = geo_data.get("isp", "Unknown")
    org = geo_data.get("org", "Unknown")
    
    output.append(f"  IP: {ip}")
    
    # Show if this IP was resolved from a domain
    if geo_data.get("resolved_from_domain"):
        output.append(f"  🌐 Resolved from domain: {geo_data['resolved_from_domain']}")
    
    # Location information
    location_parts = []
    if city:
        location_parts.append(city)
    if region and region != city:
        location_parts.append(region)
    if country:
        location_parts.append(country)
    
    if location_parts:
        output.append(f"  Location: {', '.join(location_parts)}")
    
    if geo_data.get("latitude") and geo_data.get("longitude"):
        output.append(f"  Coordinates: {geo_data['latitude']}, {geo_data['longitude']}")
    
    if isp:
        output.append(f"  ISP: {isp}")
    
    if org and org != isp:
        output.append(f"  Organization: {org}")
    
    if geo_data.get("as"):
        output.append(f"  ASN: {geo_data['as']}")
    
    # Proxy detection results
    if geo_data.get("is_proxy"):
        output.append("  🚨 PROXY DETECTED")
    
    if geo_data.get("is_hosting"):
        output.append("  🏢 Hosting Provider")
    
    if geo_data.get("is_mobile"):
        output.append("  📱 Mobile Connection")
    
    risk_level = geo_data.get("risk_level", "low")
    if risk_level != "low":
        risk_emoji = "🔴" if risk_level == "high" else "🟡"
        output.append(f"  {risk_emoji} Risk Level: {risk_level.upper()}")
    
    proxy_score = geo_data.get("proxy_score", 0)
    if proxy_score > 0:
        output.append(f"  Proxy Score: {proxy_score}")
    
    # Show indicators if verbose or high risk
    indicators = geo_data.get("indicators_found", [])
    if indicators and (verbose or risk_level in ["medium", "high"]):
        output.append(f"  Indicators: {', '.join(indicators)}")
    
    # Additional details in verbose mode
    if verbose:
        if geo_data.get("timezone"):
            output.append(f"  Timezone: {geo_data['timezone']}")
        if geo_data.get("zip"):
            output.append(f"  Postal Code: {geo_data['zip']}")
        if geo_data.get("source"):
            output.append(f"  Data Source: {geo_data['source']}")
    
    return "\n".join(output)

def format_cve_result(cve_data: Dict[str, Any], index: int, verbose: bool = False) -> str:
    """Format a CVE result for display"""
    output = []
    output.append(f"[{index}] (CVE)")
    output.append(f"  CVE ID: {cve_data.get('cve_id', 'Unknown')}")
    
    aliases = cve_data.get('aliases', [])
    if aliases:
        output.append(f"  Aliases: {', '.join(aliases)}")
    
    description = cve_data.get('description', '')
    if description:
        # Truncate long descriptions unless verbose
        if len(description) > 200 and not verbose:
            description = description[:200] + "..."
        output.append(f"  Description: {description}")
    
    references = cve_data.get('references', [])
    if references and verbose:
        output.append(f"  References ({len(references)}):")
        for ref in references[:3]:  # Show first 3 references
            if isinstance(ref, dict):
                ref_url = ref.get('url', '')
                ref_name = ref.get('name', 'Unknown')
                if ref_url:
                    output.append(f"    - {ref_name}: {ref_url}")
        if len(references) > 3:
            output.append(f"    ... and {len(references) - 3} more references")
    elif references:
        output.append(f"  References: {len(references)} available")
    
    return "\n".join(output)

def print_unified_results(results: Dict[str, Any], verbose: bool = False) -> None:
    """Print results from multiple sources in unified format"""
    all_results = []
    
    # Collect all results with source info and date for sorting
    if 'malpedia' in results and results['malpedia']:
        for ref in results['malpedia']:
            date_str = ref.get('year', ref.get('date', '0000'))
            all_results.append({
                'source': 'malpedia',
                'data': ref,
                'date': date_str,
                'date_for_sort': date_str
            })
    
    if 'otx' in results and results['otx'].get('pulses'):
        for pulse in results['otx']['pulses']:
            date_str = pulse.get('created', '')
            all_results.append({
                'source': 'otx',
                'data': pulse,
                'date': date_str,
                'date_for_sort': date_str
            })
    
    if 'rss' in results and results['rss'].get('articles'):
        for article in results['rss']['articles']:
            date_str = article.get('published', '')
            all_results.append({
                'source': 'rss',
                'data': article,
                'date': date_str,
                'date_for_sort': date_str
            })
    

    
    if 'stix' in results and results['stix'].get('objects'):
        for stix_obj in results['stix']['objects']:
            # Handle both collection results and direct objects
            obj = stix_obj.get('object', stix_obj)
            date_str = obj.get('created', obj.get('modified', ''))
            all_results.append({
                'source': 'stix',
                'data': stix_obj,
                'date': date_str,
                'date_for_sort': date_str
            })
    
    if 'threatfox' in results and results['threatfox'].get('iocs'):
        for ioc in results['threatfox']['iocs']:
            date_str = ioc.get('first_seen_utc', '')
            all_results.append({
                'source': 'threatfox',
                'data': ioc,
                'date': date_str,
                'date_for_sort': date_str
            })
    
    if 'shodan_internetdb' in results and results['shodan_internetdb'].get('results'):
        for ip_data in results['shodan_internetdb']['results']:
            # Shodan InternetDB doesn't have dates, so use current date for sorting
            current_date = datetime.now().isoformat()
            all_results.append({
                'source': 'shodan_internetdb',
                'data': ip_data,
                'date': current_date,
                'date_for_sort': current_date
            })
    
    if 'ip_geolocation' in results and results['ip_geolocation'].get('results'):
        for geo_data in results['ip_geolocation']['results']:
            # IP geolocation doesn't have dates, so use current date for sorting
            current_date = datetime.now().isoformat()
            all_results.append({
                'source': 'ip_geolocation',
                'data': geo_data,
                'date': current_date,
                'date_for_sort': current_date
            })
    
    if 'crtsh_subdomains' in results and results['crtsh_subdomains'].get('subdomains'):
        for subdomain_data in results['crtsh_subdomains']['subdomains']:
            # Use certificate dates if available, otherwise current date
            date_str = subdomain_data.get('not_before', datetime.now().isoformat())
            all_results.append({
                'source': 'crtsh_subdomains',
                'data': subdomain_data,
                'date': date_str,
                'date_for_sort': date_str
            })
    
    if 'cve' in results and results['cve'].get('cves'):
        for cve_data in results['cve']['cves']:
            # CVE doesn't have dates, so use current date for sorting
            current_date = datetime.now().isoformat()
            all_results.append({
                'source': 'cve',
                'data': cve_data,
                'date': current_date,
                'date_for_sort': current_date
            })
    
    # Sort all results by date (newest first)
    all_results.sort(key=lambda x: x['date_for_sort'], reverse=True)
    
    if not all_results:
        print("No results found across all sources.")
        return
    
    print(f"Found {len(all_results)} total results (sorted by date, newest first):")
    print("=" * 80)
    
    # Print results in unified format
    for i, result in enumerate(all_results, 1):
        source = result['source']
        data = result['data']
        
        if source == 'malpedia':
            formatted = format_malpedia_result(data, i)
        elif source == 'otx':
            formatted = format_otx_result(data, i, verbose)
        elif source == 'rss':
            formatted = format_rss_result(data, i, verbose)

        elif source == 'stix':
            formatted = format_stix_result(data, i, verbose)
        elif source == 'threatfox':
            formatted = format_threatfox_result(data, i, verbose)
        elif source == 'shodan_internetdb':
            formatted = format_shodan_internetdb_result(data, i, verbose)
        elif source == 'ip_geolocation':
            formatted = format_ip_geolocation_result(data, i, verbose)
        elif source == 'crtsh_subdomains':
            formatted = format_crtsh_subdomain_result(data, i, verbose)
        elif source == 'cve':
            formatted = format_cve_result(data, i, verbose)
        else:
            formatted = f"[{i}] (UNKNOWN SOURCE: {source})\n  Data: {data}"
            
        print(formatted)
        print("-" * 40)

def print_source_summary(results: Dict[str, Any]) -> None:
    """Print summary of results by source"""
    print("\nSource Summary:")
    
    total = 0
    if 'malpedia' in results and results['malpedia']:
        count = len(results['malpedia'])
        print(f"  Malpedia: {count} references")
        total += count
    
    if 'otx' in results and results['otx'].get('pulses'):
        count = len(results['otx']['pulses'])
        print(f"  OTX: {count} pulses")
        total += count
    
    if 'rss' in results and results['rss'].get('articles'):
        count = len(results['rss']['articles'])
        print(f"  RSS: {count} articles")
        total += count
    

    
    if 'stix' in results and results['stix'].get('objects'):
        count = len(results['stix']['objects'])
        print(f"  STIX: {count} objects")
        total += count
    
    if 'threatfox' in results and results['threatfox'].get('iocs'):
        count = len(results['threatfox']['iocs'])
        cache_age = results['threatfox'].get('cache_age', 'Unknown')
        print(f"  ThreatFox: {count} IOCs (cache: {cache_age})")
        total += count
    
    if 'shodan_internetdb' in results and results['shodan_internetdb'].get('results'):
        count = len(results['shodan_internetdb']['results'])
        ips_found = results['shodan_internetdb'].get('ips_found', 0)
        domains_found = results['shodan_internetdb'].get('domains_found', 0)
        if domains_found > 0:
            print(f"  Shodan InternetDB: {count} IP results ({ips_found} IPs from {domains_found} domains)")
        else:
            print(f"  Shodan InternetDB: {count} IP results ({ips_found} IPs found)")
        total += count
    
    if 'ip_geolocation' in results and results['ip_geolocation'].get('results'):
        count = len(results['ip_geolocation']['results'])
        ips_found = results['ip_geolocation'].get('ips_found', 0)
        domains_found = results['ip_geolocation'].get('domains_found', 0)
        # Count proxy detections
        proxy_count = sum(1 for result in results['ip_geolocation']['results'] if result.get('is_proxy'))
        hosting_count = sum(1 for result in results['ip_geolocation']['results'] if result.get('is_hosting'))
        if domains_found > 0:
            print(f"  IP Geolocation: {count} results ({ips_found} IPs from {domains_found} domains, {proxy_count} proxies, {hosting_count} hosting)")
        else:
            print(f"  IP Geolocation: {count} results ({ips_found} IPs, {proxy_count} proxies, {hosting_count} hosting)")
        total += count
    
    if 'crtsh_subdomains' in results and results['crtsh_subdomains'].get('subdomains'):
        count = len(results['crtsh_subdomains']['subdomains'])
        domain_searched = results['crtsh_subdomains'].get('domain_searched', 'Unknown')
        print(f"  crt.sh Subdomains: {count} subdomains for {domain_searched}")
        total += count
    
    if 'cve' in results and results['cve'].get('cves'):
        count = len(results['cve']['cves'])
        aliases_count = len(results['cve'].get('aliases_found', []))
        search_term = results['cve'].get('search_term', 'unknown')
        if aliases_count > 0:
            print(f"  CVE Database: {count} CVEs for '{search_term}' ({aliases_count} aliases found)")
        else:
            print(f"  CVE Database: {count} CVEs for '{search_term}'")
        total += count
    
    print(f"  Total: {total} results")
    
    # Print errors if any
    error_count = 0
    if 'rss' in results and results['rss'].get('errors'):
        error_count += len(results['rss']['errors'])
    
    if 'shodan_internetdb' in results and results['shodan_internetdb'].get('errors'):
        error_count += len(results['shodan_internetdb']['errors'])
    
    if 'ip_geolocation' in results and results['ip_geolocation'].get('errors'):
        error_count += len(results['ip_geolocation']['errors'])
    
    if 'crtsh_subdomains' in results and results['crtsh_subdomains'].get('errors'):
        error_count += len(results['crtsh_subdomains']['errors'])
    
    if 'cve' in results and results['cve'].get('error'):
        error_count += 1
    
    if error_count > 0:
        print(f"  Errors: {error_count} (use --verbose for details)")

def print_errors(results: Dict[str, Any], verbose: bool = False) -> None:
    """Print error details if verbose mode is enabled"""
    if not verbose:
        return
    
    errors_found = False
    
    if 'rss' in results and results['rss'].get('errors'):
        errors_found = True
        print(f"\nRSS Errors ({len(results['rss']['errors'])}):")
        for error in results['rss']['errors']:
            print(f"  - {error['feed']}: {error['error']}")
            print(f"    Details: {error['details']}")
    
    if 'shodan_internetdb' in results and results['shodan_internetdb'].get('errors'):
        errors_found = True
        print(f"\nShodan InternetDB Errors ({len(results['shodan_internetdb']['errors'])}):")
        for error in results['shodan_internetdb']['errors']:
            ip = error.get('ip', 'Unknown IP')
            domain = error.get('domain')
            error_msg = error.get('error', 'Unknown error')
            if domain:
                print(f"  - {ip} (from {domain}): {error_msg}")
            else:
                print(f"  - {ip}: {error_msg}")
    
    # Show DNS resolution details if verbose
    if verbose and 'shodan_internetdb' in results and results['shodan_internetdb'].get('dns_resolutions'):
        print(f"\nDNS Resolutions ({len(results['shodan_internetdb']['dns_resolutions'])}):")
        for resolution in results['shodan_internetdb']['dns_resolutions']:
            domain = resolution.get('domain')
            ips = resolution.get('ips', [])
            types = resolution.get('types', [])
            print(f"  - {domain}:")
            for ip, record_type in zip(ips, types):
                print(f"    {record_type}: {ip}")
    
    if 'ip_geolocation' in results and results['ip_geolocation'].get('errors'):
        errors_found = True
        print(f"\nIP Geolocation Errors ({len(results['ip_geolocation']['errors'])}):")
        for error in results['ip_geolocation']['errors']:
            print(f"  - {error.get('ip', 'Unknown IP')}: {error.get('error', 'Unknown error')}")
    
    if 'crtsh_subdomains' in results and results['crtsh_subdomains'].get('errors'):
        errors_found = True
        print(f"\ncrt.sh Subdomain Errors ({len(results['crtsh_subdomains']['errors'])}):")
        for error in results['crtsh_subdomains']['errors']:
            print(f"  - {error.get('domain', 'Unknown domain')}: {error.get('error', 'Unknown error')}")
    
    if 'cve' in results and results['cve'].get('error'):
        errors_found = True
        print(f"\nCVE Database Error:")
        print(f"  - {results['cve']['error']}")
    
    if not errors_found and verbose:
        print("\nNo errors encountered.") 