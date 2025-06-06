#!/usr/bin/env python3
"""
RSS Feed Connectivity Tester

This tool tests all RSS feeds from rss.txt with a 5-second timeout
and identifies feeds that are not responding.
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple

class FeedTester:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (RSS Feed Checker/1.0)',
            'Accept': 'application/rss+xml, application/xml, text/xml, */*'
        })
        
    def test_feed(self, feed_name: str, feed_url: str) -> Dict:
        """Test a single RSS feed"""
        result = {
            'name': feed_name,
            'url': feed_url,
            'status': 'unknown',
            'response_time': 0,
            'error': None,
            'http_status': None,
            'content_type': None,
            'is_valid_xml': False
        }
        
        start_time = time.time()
        
        try:
            print(f"Testing: {feed_name[:50]:<50} ... ", end="", flush=True)
            
            response = self.session.get(feed_url, timeout=self.timeout, allow_redirects=True)
            response_time = time.time() - start_time
            result['response_time'] = round(response_time, 2)
            result['http_status'] = response.status_code
            result['content_type'] = response.headers.get('content-type', 'unknown')
            
            if response.status_code == 200:
                # Try to parse as XML to verify it's valid RSS/XML
                try:
                    ET.fromstring(response.content)
                    result['is_valid_xml'] = True
                    result['status'] = 'active'
                    print(f"✅ OK ({response_time:.2f}s)")
                except ET.ParseError as e:
                    result['status'] = 'invalid_xml'
                    result['error'] = f"Invalid XML: {str(e)[:100]}"
                    print(f"⚠️  Invalid XML ({response_time:.2f}s)")
            else:
                result['status'] = 'http_error'
                result['error'] = f"HTTP {response.status_code}"
                print(f"❌ HTTP {response.status_code} ({response_time:.2f}s)")
                
        except requests.exceptions.Timeout:
            result['status'] = 'timeout'
            result['error'] = f'Timeout after {self.timeout}s'
            result['response_time'] = self.timeout
            print(f"⏰ Timeout ({self.timeout}s)")
            
        except requests.exceptions.ConnectionError as e:
            result['status'] = 'connection_error'
            result['error'] = f'Connection error: {str(e)[:100]}'
            result['response_time'] = time.time() - start_time
            print(f"🔌 Connection Error ({result['response_time']:.2f}s)")
            
        except requests.exceptions.RequestException as e:
            result['status'] = 'request_error'
            result['error'] = f'Request error: {str(e)[:100]}'
            result['response_time'] = time.time() - start_time
            print(f"❌ Error ({result['response_time']:.2f}s)")
            
        except Exception as e:
            result['status'] = 'unknown_error'
            result['error'] = f'Unknown error: {str(e)[:100]}'
            result['response_time'] = time.time() - start_time
            print(f"❓ Unknown Error ({result['response_time']:.2f}s)")
            
        return result

def determine_category(feed_name: str, feed_url: str) -> str:
    """Determine the category of a feed based on its name and URL"""
    name_lower = feed_name.lower()
    url_lower = feed_url.lower()
    
    # Government and official sources
    if any(keyword in name_lower for keyword in ['cisa', 'nsa', 'fbi', 'cert', 'ncsc', 'enisa', 'government']):
        return 'government'
    if any(keyword in url_lower for keyword in ['gov.', '.gov', 'cert.', 'cisa.', 'nsa.', 'fbi.']):
        return 'government'
    
    # Threat intelligence and security vendors
    if any(keyword in name_lower for keyword in ['crowdstrike', 'fireeye', 'mandiant', 'symantec', 'palo alto', 'check point', 'fortinet']):
        return 'threat_intelligence'
    if any(keyword in name_lower for keyword in ['x-force', 'talos', 'anomali', 'threatconnect', 'recorded future']):
        return 'threat_intelligence'
    
    # Security research and labs
    if any(keyword in name_lower for keyword in ['research', 'labs', 'security', 'malware']):
        return 'security_research'
    if any(keyword in name_lower for keyword in ['trail of bits', 'project zero', 'rapid7', 'qualys']):
        return 'security_research'
    
    # News and media
    if any(keyword in name_lower for keyword in ['news', 'hacker news', 'register', 'security affairs', 'krebs']):
        return 'security_news'
    
    # OSINT and intelligence
    if any(keyword in name_lower for keyword in ['osint', 'bellingcat', 'shodan', 'passive']):
        return 'osint'
    
    # Academic and educational
    if any(keyword in name_lower for keyword in ['mit', 'ieee', 'usenix', 'sans', 'university']):
        return 'academic'
    
    # Cloud security
    if any(keyword in name_lower for keyword in ['aws', 'azure', 'google cloud', 'cloud']):
        return 'cloud_security'
    
    # ICS/SCADA
    if any(keyword in name_lower for keyword in ['ics', 'scada', 'dragos', 'claroty']):
        return 'ics_security'
    
    # Default category
    return 'general_security'

def load_feeds_from_file(filename: str = "rss.txt") -> List[Tuple[str, str]]:
    """Load feeds from rss.txt file"""
    feeds = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#') and '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        feed_name = parts[0].strip()
                        feed_url = parts[1].strip()
                        if feed_name and feed_url:
                            feeds.append((feed_name, feed_url))
                        else:
                            print(f"⚠️  Line {line_num}: Empty name or URL")
                    else:
                        print(f"⚠️  Line {line_num}: Invalid format - {line}")
    except FileNotFoundError:
        print(f"❌ Error: {filename} not found")
        return []
    except Exception as e:
        print(f"❌ Error reading {filename}: {e}")
        return []
    
    return feeds

def print_summary(results: List[Dict]):
    """Print a summary of test results"""
    
    # Categorize results
    active = [r for r in results if r['status'] == 'active']
    inactive = [r for r in results if r['status'] != 'active']
    timeouts = [r for r in results if r['status'] == 'timeout']
    connection_errors = [r for r in results if r['status'] == 'connection_error']
    http_errors = [r for r in results if r['status'] == 'http_error']
    invalid_xml = [r for r in results if r['status'] == 'invalid_xml']
    
    print("\n" + "=" * 80)
    print("📊 RSS FEED TEST SUMMARY")
    print("=" * 80)
    
    print(f"✅ Active feeds:        {len(active):3d}")
    print(f"❌ Inactive feeds:      {len(inactive):3d}")
    print(f"   └─ Timeouts:         {len(timeouts):3d}")
    print(f"   └─ Connection errors: {len(connection_errors):3d}")
    print(f"   └─ HTTP errors:      {len(http_errors):3d}")
    print(f"   └─ Invalid XML:      {len(invalid_xml):3d}")
    print(f"📊 Total tested:        {len(results):3d}")
    
    # Calculate average response time for active feeds
    if active:
        avg_response = sum(r['response_time'] for r in active) / len(active)
        print(f"⏱️  Average response:    {avg_response:.2f}s")
    
    # Print inactive feeds
    if inactive:
        print(f"\n❌ INACTIVE FEEDS ({len(inactive)}):")
        print("-" * 80)
        
        for result in sorted(inactive, key=lambda x: x['name'].lower()):
            print(f"Name: {result['name']}")
            print(f"URL:  {result['url']}")
            print(f"Issue: {result['status'].replace('_', ' ').title()} - {result['error']}")
            print(f"Time: {result['response_time']:.2f}s")
            print("-" * 40)
    
    # Print slowest active feeds
    if active:
        slowest = sorted(active, key=lambda x: x['response_time'], reverse=True)[:5]
        print(f"\n🐌 SLOWEST ACTIVE FEEDS:")
        print("-" * 80)
        for result in slowest:
            print(f"{result['name'][:50]:<50} {result['response_time']:>6.2f}s")

def main():
    """Main function"""
    print("🔍 RSS Feed Connectivity Tester")
    print("=" * 80)
    
    # Load feeds
    feeds = load_feeds_from_file()
    if not feeds:
        print("❌ No feeds to test!")
        return
    
    print(f"📡 Found {len(feeds)} feeds to test")
    print(f"⏰ Timeout: 5 seconds per feed")
    print(f"🚀 Testing with concurrent connections...")
    print("-" * 80)
    
    # Test feeds concurrently
    tester = FeedTester(timeout=5)
    results = []
    
    start_time = time.time()
    
    # Use ThreadPoolExecutor for concurrent testing
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks
        future_to_feed = {
            executor.submit(tester.test_feed, name, url): (name, url) 
            for name, url in feeds
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_feed):
            result = future.result()
            results.append(result)
    
    total_time = time.time() - start_time
    
    print(f"\n⏱️  Total testing time: {total_time:.2f} seconds")
    
    # Print summary
    print_summary(results)
    
    # Save inactive feeds to file
    inactive_feeds = [r for r in results if r['status'] != 'active']
    if inactive_feeds:
        with open('inactive_feeds.txt', 'w') as f:
            f.write("# Inactive RSS Feeds\n")
            f.write(f"# Tested on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Format: feed_name|feed_url|status|error\n\n")
            
            for result in inactive_feeds:
                f.write(f"{result['name']}|{result['url']}|{result['status']}|{result['error']}\n")
        
        print(f"\n💾 Inactive feeds saved to: inactive_feeds.txt")
    
    # Save active feeds to file (can replace rss.txt)
    active_feeds = [r for r in results if r['status'] == 'active']
    if active_feeds:
        with open('active_feeds.txt', 'w') as f:
            f.write("# Active RSS Feeds\n")
            f.write(f"# Tested and verified on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Format: feed_name|feed_url|category\n")
            f.write("# All feeds below responded successfully with valid RSS/XML content\n\n")
            
            # Sort feeds by response time (fastest first) and then by name
            sorted_active = sorted(active_feeds, key=lambda x: (x['response_time'], x['name'].lower()))
            
            for result in sorted_active:
                # Try to determine category from feed name/URL
                category = determine_category(result['name'], result['url'])
                f.write(f"{result['name']}|{result['url']}|{category}\n")
        
        print(f"✅ Active feeds saved to: active_feeds.txt ({len(active_feeds)} feeds)")
        print(f"   You can replace rss.txt with: cp active_feeds.txt rss.txt")

if __name__ == "__main__":
    main() 