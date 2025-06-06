#!/usr/bin/env python3

import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import base64

def escape_html(text: str) -> str:
    """Safely escape text for HTML output"""
    if not text:
        return ""
    return html.escape(str(text))

def format_timestamp(timestamp: str) -> str:
    """Format ISO timestamp for display"""
    if not timestamp:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return timestamp

def get_report_css() -> str:
    """Get CSS styles for HTML reports"""
    return """
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .summary {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary h2 {
            margin: 0 0 20px 0;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        .summary-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        .summary-item .label {
            font-weight: 600;
            color: #555;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .summary-item .value {
            font-size: 1.4em;
            font-weight: 700;
            color: #2c3e50;
            margin-top: 5px;
        }
        .source-section {
            background: white;
            margin-bottom: 30px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .source-header {
            background: #34495e;
            color: white;
            padding: 20px;
            margin: 0;
        }
        .source-header h3 {
            margin: 0;
            font-size: 1.5em;
        }
        .source-stats {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 5px;
        }
        .results-container {
            padding: 0;
        }
        .result-item {
            border-bottom: 1px solid #eee;
            padding: 25px;
        }
        .result-item:last-child {
            border-bottom: none;
        }
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .result-index {
            background: #3498db;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
        }
        .result-date {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .result-title {
            font-size: 1.3em;
            font-weight: 600;
            color: #2c3e50;
            margin: 10px 0;
        }
        .result-content {
            color: #555;
            line-height: 1.6;
        }
        .result-meta {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #eee;
        }
        .meta-item {
            display: inline-block;
            background: #ecf0f1;
            padding: 5px 10px;
            margin: 2px 5px 2px 0;
            border-radius: 4px;
            font-size: 0.85em;
            color: #555;
        }
        .meta-label {
            font-weight: 600;
            color: #2c3e50;
        }
        .link {
            color: #3498db;
            text-decoration: none;
            word-break: break-all;
        }
        .link:hover {
            text-decoration: underline;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            margin: 2px;
        }
        .badge-risk-high { background: #e74c3c; color: white; }
        .badge-risk-medium { background: #f39c12; color: white; }
        .badge-risk-low { background: #95a5a6; color: white; }
        .badge-proxy { background: #e74c3c; color: white; }
        .badge-hosting { background: #3498db; color: white; }
        .badge-mobile { background: #2ecc71; color: white; }
        .no-results {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
            font-style: italic;
        }
        .errors-section {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
        .errors-section h3 {
            color: #c53030;
            margin: 0 0 15px 0;
        }
        .error-item {
            background: white;
            border-left: 4px solid #e53e3e;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 6px 6px 0;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #7f8c8d;
            border-top: 1px solid #eee;
            margin-top: 50px;
        }
        @media (max-width: 768px) {
            body { padding: 10px; }
            .header h1 { font-size: 2em; }
            .summary-grid { grid-template-columns: 1fr; }
            .result-header { flex-direction: column; align-items: flex-start; }
        }
    </style>
    """

def generate_html_report(results: Dict[str, Any], search_term: str) -> str:
    """Generate HTML report from search results"""
    
    # Calculate summary statistics
    total_results = 0
    sources_with_results = 0
    total_errors = 0
    
    for source_key, source_data in results.items():
        if isinstance(source_data, dict):
            if source_key == 'malpedia' and source_data:
                total_results += len(source_data)
                sources_with_results += 1
            elif source_key == 'otx' and source_data.get('pulses'):
                total_results += len(source_data['pulses'])
                sources_with_results += 1
            elif source_key == 'rss' and source_data.get('articles'):
                total_results += len(source_data['articles'])
                sources_with_results += 1
            elif source_key == 'stix' and source_data.get('objects'):
                total_results += len(source_data['objects'])
                sources_with_results += 1
            elif source_key == 'threatfox' and source_data.get('iocs'):
                total_results += len(source_data['iocs'])
                sources_with_results += 1
            elif source_key in ['shodan_internetdb', 'ip_geolocation'] and source_data.get('results'):
                total_results += len(source_data['results'])
                sources_with_results += 1
            elif source_key == 'crtsh_subdomains' and source_data.get('subdomains'):
                total_results += len(source_data['subdomains'])
                sources_with_results += 1
            
            # Count errors
            if source_data.get('errors'):
                total_errors += len(source_data['errors'])
    
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Threat Intelligence Report - {escape_html(search_term)}</title>
        {get_report_css()}
    </head>
    <body>
        <div class="header">
            <h1>🔍 Threat Intelligence Report</h1>
            <div class="subtitle">Search Results for: "{escape_html(search_term)}"</div>
            <div class="subtitle">Generated: {current_time}</div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="label">Total Results</div>
                    <div class="value">{total_results:,}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Sources Searched</div>
                    <div class="value">{sources_with_results}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Search Term</div>
                    <div class="value">{escape_html(search_term)}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Report Date</div>
                    <div class="value">{current_time.split()[0]}</div>
                </div>
            </div>
        </div>
    """
    
    # Generate content for each source
    html_content += generate_malpedia_html(results.get('malpedia', []))
    html_content += generate_otx_html(results.get('otx', {}))
    html_content += generate_rss_html(results.get('rss', {}))
    html_content += generate_stix_html(results.get('stix', {}))
    html_content += generate_threatfox_html(results.get('threatfox', {}))
    html_content += generate_shodan_html(results.get('shodan_internetdb', {}))
    html_content += generate_ipgeo_html(results.get('ip_geolocation', {}))
    html_content += generate_crtsh_html(results.get('crtsh_subdomains', {}))
    
    # Add errors section if there are any
    if total_errors > 0:
        html_content += generate_errors_html(results)
    
    html_content += """
        <div class="footer">
            Generated by IntelBay Threat Intelligence Platform<br>
            <small>This report contains aggregated intelligence from multiple open sources</small>
        </div>
    </body>
    </html>
    """
    
    return html_content

def generate_malpedia_html(malpedia_results: List[Dict[str, Any]]) -> str:
    """Generate HTML for Malpedia results"""
    if not malpedia_results:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>📚 Malpedia - Malware Research Bibliography</h3>
                <div class="source-stats">{len(malpedia_results)} research papers found</div>
            </div>
            <div class="results-container">
    """
    
    for i, ref in enumerate(malpedia_results, 1):
        title = ref.get('title', 'Unknown Title')
        authors = ref.get('author', 'Unknown Author')
        year = ref.get('year', ref.get('date', 'Unknown Year'))
        url = ref.get('url', '')
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">{escape_html(str(year))}</span>
                    </div>
                    <div class="result-title">{escape_html(title)}</div>
                    <div class="result-content">
                        <strong>Authors:</strong> {escape_html(authors)}
                    </div>
                    <div class="result-meta">
                        <span class="meta-item"><span class="meta-label">Year:</span> {escape_html(str(year))}</span>
                        {f'<a href="{escape_html(url)}" class="link" target="_blank">View Paper</a>' if url else ''}
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_otx_html(otx_results: Dict[str, Any]) -> str:
    """Generate HTML for OTX results"""
    pulses = otx_results.get('pulses', [])
    if not pulses:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>🌐 AlienVault OTX - Open Threat Exchange</h3>
                <div class="source-stats">{len(pulses)} threat intelligence pulses found</div>
            </div>
            <div class="results-container">
    """
    
    for i, pulse in enumerate(pulses, 1):
        name = pulse.get('name', 'Unknown Pulse')
        description = pulse.get('description', '')
        created = format_timestamp(pulse.get('created', ''))
        author = pulse.get('author_name', 'Unknown Author')
        tags = pulse.get('tags', [])
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">{created}</span>
                    </div>
                    <div class="result-title">{escape_html(name)}</div>
                    <div class="result-content">{escape_html(description[:500])}{'...' if len(description) > 500 else ''}</div>
                    <div class="result-meta">
                        <span class="meta-item"><span class="meta-label">Author:</span> {escape_html(author)}</span>
                        {' '.join(f'<span class="badge badge-risk-low">{escape_html(tag)}</span>' for tag in tags[:5])}
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_rss_html(rss_results: Dict[str, Any]) -> str:
    """Generate HTML for RSS results"""
    articles = rss_results.get('articles', [])
    if not articles:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>📰 RSS Feeds - Cybersecurity News</h3>
                <div class="source-stats">{len(articles)} articles found from cybersecurity feeds</div>
            </div>
            <div class="results-container">
    """
    
    for i, article in enumerate(articles, 1):
        title = article.get('title', 'Unknown Title')
        summary = article.get('summary', '')
        published = format_timestamp(article.get('published', ''))
        feed_name = article.get('feed_name', 'Unknown Feed')
        category = article.get('feed_category', 'Unknown Category')
        link = article.get('link', '')
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">{published}</span>
                    </div>
                    <div class="result-title">{escape_html(title)}</div>
                    <div class="result-content">{escape_html(summary)}</div>
                    <div class="result-meta">
                        <span class="meta-item"><span class="meta-label">Source:</span> {escape_html(feed_name)}</span>
                        <span class="meta-item"><span class="meta-label">Category:</span> {escape_html(category)}</span>
                        {f'<a href="{escape_html(link)}" class="link" target="_blank">Read Article</a>' if link else ''}
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_stix_html(stix_results: Dict[str, Any]) -> str:
    """Generate HTML for STIX results"""
    objects = stix_results.get('objects', [])
    if not objects:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>🔗 STIX/TAXII - Structured Threat Intelligence</h3>
                <div class="source-stats">{len(objects)} STIX objects found</div>
            </div>
            <div class="results-container">
    """
    
    for i, stix_obj in enumerate(objects, 1):
        obj = stix_obj.get('object', stix_obj)
        name = obj.get('name', obj.get('pattern', 'Unknown Object'))
        obj_type = obj.get('type', 'unknown')
        created = format_timestamp(obj.get('created', ''))
        description = obj.get('description', '')
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">{created}</span>
                    </div>
                    <div class="result-title">{escape_html(name)}</div>
                    <div class="result-content">{escape_html(description[:500])}{'...' if len(description) > 500 else ''}</div>
                    <div class="result-meta">
                        <span class="meta-item"><span class="meta-label">Type:</span> {escape_html(obj_type)}</span>
                        <span class="meta-item"><span class="meta-label">ID:</span> {escape_html(obj.get('id', 'Unknown'))}</span>
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_threatfox_html(threatfox_results: Dict[str, Any]) -> str:
    """Generate HTML for ThreatFox results"""
    iocs = threatfox_results.get('iocs', [])
    if not iocs:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>🦊 ThreatFox - Indicators of Compromise</h3>
                <div class="source-stats">{len(iocs)} IOCs found from abuse.ch ThreatFox</div>
            </div>
            <div class="results-container">
    """
    
    for i, ioc in enumerate(iocs, 1):
        ioc_value = ioc.get('ioc_value', 'Unknown IOC')
        ioc_type = ioc.get('ioc_type', 'unknown')
        malware = ioc.get('malware_printable', ioc.get('malware', 'Unknown'))
        first_seen = format_timestamp(ioc.get('first_seen_utc', ''))
        confidence = ioc.get('confidence_level', 0)
        threat_type = ioc.get('threat_type', 'Unknown')
        
        confidence_class = 'high' if confidence >= 75 else 'medium' if confidence >= 50 else 'low'
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">{first_seen}</span>
                    </div>
                    <div class="result-title">{escape_html(ioc_value)}</div>
                    <div class="result-content">
                        <strong>Malware:</strong> {escape_html(malware)}<br>
                        <strong>Threat Type:</strong> {escape_html(threat_type)}
                    </div>
                    <div class="result-meta">
                        <span class="meta-item"><span class="meta-label">IOC Type:</span> {escape_html(ioc_type)}</span>
                        <span class="badge badge-risk-{confidence_class}">Confidence: {confidence}%</span>
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_shodan_html(shodan_results: Dict[str, Any]) -> str:
    """Generate HTML for Shodan InternetDB results"""
    results = shodan_results.get('results', [])
    if not results:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>🔍 Shodan InternetDB - IP Intelligence</h3>
                <div class="source-stats">{len(results)} IP addresses analyzed</div>
            </div>
            <div class="results-container">
    """
    
    for i, ip_data in enumerate(results, 1):
        ip = ip_data.get('ip', 'Unknown IP')
        ports = ip_data.get('ports', [])
        vulns = ip_data.get('vulns', [])
        hostnames = ip_data.get('hostnames', [])
        tags = ip_data.get('tags', [])
        domain = ip_data.get('resolved_from_domain', '')
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">Current</span>
                    </div>
                    <div class="result-title">{escape_html(ip)}</div>
                    {f'<div class="result-content"><strong>🌐 Resolved from domain:</strong> {escape_html(domain)}</div>' if domain else ''}
                    <div class="result-content">
                        {f'<strong>Open Ports:</strong> {", ".join(map(str, ports[:10]))}{"..." if len(ports) > 10 else ""}<br>' if ports else ''}
                        {f'<strong>Hostnames:</strong> {", ".join(hostnames[:3])}{"..." if len(hostnames) > 3 else ""}<br>' if hostnames else ''}
                        {f'<strong>Vulnerabilities:</strong> {len(vulns)} found<br>' if vulns else ''}
                    </div>
                    <div class="result-meta">
                        {' '.join(f'<span class="badge badge-risk-medium">{escape_html(tag)}</span>' for tag in tags[:5])}
                        {f'<span class="badge badge-risk-high">{len(vulns)} Vulns</span>' if vulns else ''}
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_ipgeo_html(ipgeo_results: Dict[str, Any]) -> str:
    """Generate HTML for IP Geolocation results"""
    results = ipgeo_results.get('results', [])
    if not results:
        return ""
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>🌍 IP Geolocation & Proxy Detection</h3>
                <div class="source-stats">{len(results)} IP addresses geolocated</div>
            </div>
            <div class="results-container">
    """
    
    for i, geo_data in enumerate(results, 1):
        ip = geo_data.get('ip', 'Unknown IP')
        city = geo_data.get('city', '')
        country = geo_data.get('country', '')
        isp = geo_data.get('isp', '')
        is_proxy = geo_data.get('is_proxy', False)
        is_hosting = geo_data.get('is_hosting', False)
        risk_level = geo_data.get('risk_level', 'low')
        domain = geo_data.get('resolved_from_domain', '')
        
        location = f"{city}, {country}" if city and country else country or "Unknown"
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">Current</span>
                    </div>
                    <div class="result-title">{escape_html(ip)}</div>
                    {f'<div class="result-content"><strong>🌐 Resolved from domain:</strong> {escape_html(domain)}</div>' if domain else ''}
                    <div class="result-content">
                        <strong>Location:</strong> {escape_html(location)}<br>
                        <strong>ISP:</strong> {escape_html(isp)}
                    </div>
                    <div class="result-meta">
                        <span class="badge badge-risk-{risk_level}">Risk: {risk_level.upper()}</span>
                        {f'<span class="badge badge-proxy">PROXY</span>' if is_proxy else ''}
                        {f'<span class="badge badge-hosting">HOSTING</span>' if is_hosting else ''}
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_crtsh_html(crtsh_results: Dict[str, Any]) -> str:
    """Generate HTML for crt.sh subdomain results"""
    subdomains = crtsh_results.get('subdomains', [])
    if not subdomains:
        return ""
    
    domain_searched = crtsh_results.get('domain_searched', 'Unknown')
    
    html = f"""
        <div class="source-section">
            <div class="source-header">
                <h3>🔍 crt.sh - Subdomain Enumeration</h3>
                <div class="source-stats">{len(subdomains)} subdomains found for {escape_html(domain_searched)}</div>
            </div>
            <div class="results-container">
    """
    
    for i, subdomain_data in enumerate(subdomains, 1):
        subdomain = subdomain_data.get('subdomain', 'Unknown')
        certificate_id = subdomain_data.get('certificate_id', '')
        issuer = subdomain_data.get('issuer', '')
        not_before = subdomain_data.get('not_before', '')
        not_after = subdomain_data.get('not_after', '')
        common_name = subdomain_data.get('common_name', '')
        
        # Format certificate validity dates
        valid_from = format_timestamp(not_before) if not_before else 'Unknown'
        valid_until = format_timestamp(not_after) if not_after else 'Unknown'
        
        html += f"""
                <div class="result-item">
                    <div class="result-header">
                        <span class="result-index">#{i}</span>
                        <span class="result-date">{valid_from}</span>
                    </div>
                    <div class="result-title">{escape_html(subdomain)}</div>
                    <div class="result-content">
                        <strong>Certificate ID:</strong> {escape_html(certificate_id)}<br>
                        {f'<strong>Common Name:</strong> {escape_html(common_name)}<br>' if common_name and common_name != subdomain else ''}
                        {f'<strong>Issuer:</strong> {escape_html(issuer)}<br>' if issuer else ''}
                        <strong>Valid From:</strong> {valid_from}<br>
                        <strong>Valid Until:</strong> {valid_until}
                    </div>
                    <div class="result-meta">
                        <span class="meta-item"><span class="meta-label">Domain:</span> {escape_html(domain_searched)}</span>
                        <span class="meta-item"><span class="meta-label">Certificate:</span> {escape_html(certificate_id)}</span>
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    return html

def generate_errors_html(results: Dict[str, Any]) -> str:
    """Generate HTML for errors section"""
    all_errors = []
    
    for source_key, source_data in results.items():
        if isinstance(source_data, dict) and source_data.get('errors'):
            for error in source_data['errors']:
                all_errors.append({
                    'source': source_key,
                    'error': error
                })
    
    if not all_errors:
        return ""
    
    html = f"""
        <div class="errors-section">
            <h3>⚠️ Errors and Warnings ({len(all_errors)} total)</h3>
    """
    
    for error_info in all_errors:
        source = error_info['source']
        error = error_info['error']
        
        html += f"""
            <div class="error-item">
                <strong>{source.upper()}:</strong> {escape_html(str(error.get('error', error)))}
                {f'<br><small>{escape_html(str(error.get("details", "")))}</small>' if error.get('details') else ''}
            </div>
        """
    
    html += """
        </div>
    """
    
    return html

def generate_json_report(results: Dict[str, Any], search_term: str) -> str:
    """Generate JSON report from search results"""
    
    report_data = {
        "metadata": {
            "search_term": search_term,
            "generated_at": datetime.now().isoformat(),
            "generator": "IntelBay Threat Intelligence Platform",
            "version": "1.0"
        },
        "summary": {
            "total_results": 0,
            "sources_searched": 0,
            "total_errors": 0,
            "sources_with_results": []
        },
        "results": results
    }
    
    # Calculate summary
    for source_key, source_data in results.items():
        if isinstance(source_data, dict):
            has_results = False
            result_count = 0
            
            if source_key == 'malpedia' and source_data:
                result_count = len(source_data)
                has_results = True
            elif source_key == 'otx' and source_data.get('pulses'):
                result_count = len(source_data['pulses'])
                has_results = True
            elif source_key == 'rss' and source_data.get('articles'):
                result_count = len(source_data['articles'])
                has_results = True
            elif source_key == 'stix' and source_data.get('objects'):
                result_count = len(source_data['objects'])
                has_results = True
            elif source_key == 'threatfox' and source_data.get('iocs'):
                result_count = len(source_data['iocs'])
                has_results = True
            elif source_key in ['shodan_internetdb', 'ip_geolocation'] and source_data.get('results'):
                result_count = len(source_data['results'])
                has_results = True
            elif source_key == 'crtsh_subdomains' and source_data.get('subdomains'):
                result_count = len(source_data['subdomains'])
                has_results = True
            
            if has_results:
                report_data["summary"]["total_results"] += result_count
                report_data["summary"]["sources_searched"] += 1
                report_data["summary"]["sources_with_results"].append({
                    "source": source_key,
                    "result_count": result_count
                })
            
            if source_data.get('errors'):
                report_data["summary"]["total_errors"] += len(source_data['errors'])
    
    return json.dumps(report_data, indent=2, ensure_ascii=False, default=str)

def save_report(results: Dict[str, Any], search_term: str, report_format: str, output_dir: str = None) -> str:
    """
    Save search results as a report
    
    Args:
        results: Search results dictionary
        search_term: Original search term
        report_format: 'html', 'json', or 'both'
        output_dir: Directory to save reports (default: current directory)
        
    Returns:
        Path to saved report(s)
    """
    
    if output_dir is None:
        output_dir = Path.cwd()
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create safe filename from search term
    safe_search_term = "".join(c for c in search_term if c.isalnum() or c in (' ', '-', '_')).rstrip()[:50]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"threat_intel_report_{safe_search_term}_{timestamp}".replace(' ', '_')
    
    saved_files = []
    
    if report_format in ['html', 'both']:
        html_content = generate_html_report(results, search_term)
        html_file = output_dir / f"{base_filename}.html"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        saved_files.append(str(html_file))
    
    if report_format in ['json', 'both']:
        json_content = generate_json_report(results, search_term)
        json_file = output_dir / f"{base_filename}.json"
        
        with open(json_file, 'w', encoding='utf-8') as f:
            f.write(json_content)
        
        saved_files.append(str(json_file))
    
    return ", ".join(saved_files)

def test_report_generation():
    """Test function for report generation"""
    
    # Sample test data
    test_results = {
        'malpedia': [
            {
                'title': 'Test Malware Analysis',
                'author': 'Security Researcher',
                'year': '2024',
                'url': 'https://example.com/paper1'
            }
        ],
        'threatfox': {
            'iocs': [
                {
                    'ioc_value': '192.168.1.100',
                    'ioc_type': 'ip:port',
                    'malware_printable': 'TestMalware',
                    'first_seen_utc': '2024-01-15 10:30:00',
                    'confidence_level': 85,
                    'threat_type': 'botnet_cc'
                }
            ]
        },
        'ip_geolocation': {
            'results': [
                {
                    'ip': '8.8.8.8',
                    'city': 'Mountain View',
                    'country': 'United States',
                    'isp': 'Google LLC',
                    'is_proxy': False,
                    'is_hosting': True,
                    'risk_level': 'medium'
                }
            ]
        }
    }
    
    # Generate test reports
    html_report = generate_html_report(test_results, "test search")
    json_report = generate_json_report(test_results, "test search")
    
    print("HTML Report generated successfully!")
    print("JSON Report generated successfully!")
    
    # Save test reports
    try:
        saved_files = save_report(test_results, "test_search", "both", "test_reports")
        print(f"Test reports saved: {saved_files}")
    except Exception as e:
        print(f"Error saving test reports: {e}")

if __name__ == "__main__":
    test_report_generation() 