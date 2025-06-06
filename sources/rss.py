import requests
import feedparser
from datetime import datetime, timedelta
import time
from typing import List, Dict, Any, Optional, Set
import re
from urllib.parse import urlparse
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from pathlib import Path
import pickle
import os

def load_rss_feeds() -> List[Dict[str, str]]:
    """Load RSS feeds from rss.txt configuration file"""
    feeds = []
    rss_file = Path(__file__).parent.parent / 'rss.txt'
    
    if not rss_file.exists():
        print(f"Warning: RSS configuration file not found at {rss_file}")
        return []
    
    try:
        with open(rss_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse feed line: name|url|category
                parts = line.split('|')
                if len(parts) != 3:
                    print(f"Warning: Invalid format in rss.txt line {line_num}: {line}")
                    continue
                
                name, url, category = [part.strip() for part in parts]
                feeds.append({
                    "name": name,
                    "url": url, 
                    "category": category
                })
    
    except Exception as e:
        print(f"Error loading RSS feeds from {rss_file}: {e}")
        return []
    
    return feeds

# Load RSS feeds from configuration file
RSS_FEEDS = load_rss_feeds()

# RSS cache configuration
RSS_CACHE_DIR = Path(__file__).parent.parent / 'cache' / 'rss'
RSS_CACHE_DURATION = 3600  # 1 hour in seconds

def ensure_cache_dir():
    """Ensure cache directory exists"""
    RSS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

def get_cache_file_path(feed_url: str) -> Path:
    """Get cache file path for a feed URL"""
    feed_hash = hashlib.sha256(feed_url.encode()).hexdigest()
    return RSS_CACHE_DIR / f"feed_{feed_hash}.pkl"

def is_cache_fresh(cache_file: Path) -> bool:
    """Check if cache file is fresh (within cache duration)"""
    if not cache_file.exists():
        return False
    
    cache_age = time.time() - cache_file.stat().st_mtime
    return cache_age < RSS_CACHE_DURATION

def save_feed_to_cache(feed_url: str, parsed_feed: Any) -> None:
    """Save parsed feed to cache"""
    try:
        ensure_cache_dir()
        cache_file = get_cache_file_path(feed_url)
        
        cache_data = {
            'feed_url': feed_url,
            'parsed_feed': parsed_feed,
            'cached_at': time.time()
        }
        
        with open(cache_file, 'wb') as f:
            pickle.dump(cache_data, f)
    except Exception as e:
        # Cache failures shouldn't break the search
        pass

def load_feed_from_cache(feed_url: str) -> Optional[Any]:
    """Load parsed feed from cache if available and fresh"""
    try:
        cache_file = get_cache_file_path(feed_url)
        
        if not is_cache_fresh(cache_file):
            return None
        
        with open(cache_file, 'rb') as f:
            cache_data = pickle.load(f)
        
        return cache_data.get('parsed_feed')
    except Exception as e:
        # Cache failures shouldn't break the search
        return None

def clear_rss_cache() -> None:
    """Clear all RSS cache files"""
    try:
        if RSS_CACHE_DIR.exists():
            for cache_file in RSS_CACHE_DIR.glob("feed_*.pkl"):
                cache_file.unlink()
    except Exception as e:
        print(f"Warning: Could not clear RSS cache: {e}")

def get_cache_stats() -> Dict[str, Any]:
    """Get RSS cache statistics"""
    stats = {
        "total_cached_feeds": 0,
        "cache_size_bytes": 0,
        "oldest_cache": None,
        "newest_cache": None
    }
    
    try:
        if not RSS_CACHE_DIR.exists():
            return stats
        
        cache_files = list(RSS_CACHE_DIR.glob("feed_*.pkl"))
        stats["total_cached_feeds"] = len(cache_files)
        
        if cache_files:
            total_size = sum(f.stat().st_size for f in cache_files)
            stats["cache_size_bytes"] = total_size
            
            mtimes = [f.stat().st_mtime for f in cache_files]
            stats["oldest_cache"] = datetime.fromtimestamp(min(mtimes)).isoformat()
            stats["newest_cache"] = datetime.fromtimestamp(max(mtimes)).isoformat()
    
    except Exception as e:
        pass
    
    return stats

def get_content_hash(title: str, content: str, link: str) -> str:
    """Generate a hash for content deduplication"""
    combined = f"{title}|{content}|{link}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def clean_html_content(content: str) -> str:
    """Basic HTML tag removal and content cleaning"""
    if not content:
        return ""
    
    # Remove HTML tags
    content = re.sub(r'<[^>]+>', '', content)
    # Remove extra whitespace
    content = re.sub(r'\s+', ' ', content)
    # Remove common HTML entities
    content = content.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    
    return content.strip()

def parse_feed_with_encoding_fallback(feed_url: str, use_cache: bool = True) -> Any:
    """Parse RSS feed with encoding fallback to handle character encoding issues"""
    
    # Try to load from cache first
    if use_cache:
        cached_feed = load_feed_from_cache(feed_url)
        if cached_feed is not None:
            return cached_feed
    
    try:
        # First try: Let feedparser handle encoding automatically
        parsed_feed = feedparser.parse(feed_url)
        
        # If there's a bozo exception related to encoding, try with requests first
        if (hasattr(parsed_feed, 'bozo') and parsed_feed.bozo and 
            parsed_feed.bozo_exception and 
            'encoding' in str(parsed_feed.bozo_exception).lower()):
            
            # Try to fetch with requests and explicit encoding handling
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; Intelligence Search Bot)'
            }
            
            response = requests.get(feed_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Try to detect and fix encoding issues
            content = response.content
            
            # Try UTF-8 first
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                # Fallback to latin-1 and then convert to UTF-8
                try:
                    content_str = content.decode('latin-1')
                except UnicodeDecodeError:
                    # Last resort: use errors='replace'
                    content_str = content.decode('utf-8', errors='replace')
            
            # Parse the cleaned content
            parsed_feed = feedparser.parse(content_str)
        
        # Save successful parse to cache
        if use_cache and parsed_feed and hasattr(parsed_feed, 'entries'):
            save_feed_to_cache(feed_url, parsed_feed)
        
        return parsed_feed
        
    except Exception as e:
        # Return a minimal feed object with error info
        return type('obj', (object,), {
            'bozo': True,
            'bozo_exception': e,
            'entries': []
        })()

def search_single_feed(feed_info: Dict[str, str], search_term_lower: str, since_date: datetime, reload: bool = False) -> Dict[str, Any]:
    """
    Search a single RSS feed for articles containing the search term
    
    Args:
        feed_info: Feed information dictionary
        search_term_lower: Lowercase search term
        since_date: Cutoff date for articles
        
    Returns:
        Dictionary with feed results
    """
    feed_name = feed_info["name"]
    feed_url = feed_info["url"]
    category = feed_info["category"]
    
    feed_result = {
        "feed_name": feed_name,
        "feed_category": category,
        "success": False,
        "articles": [],
        "error": None
    }
    
    try:
        # Parse RSS feed with encoding handling (skip cache if reload is requested)
        parsed_feed = parse_feed_with_encoding_fallback(feed_url, use_cache=not reload)
        
        if hasattr(parsed_feed, 'bozo') and parsed_feed.bozo:
            # Only treat as error if there are no entries and it's a significant parsing error
            if not parsed_feed.entries and parsed_feed.bozo_exception:
                error_msg = str(parsed_feed.bozo_exception)
                # Skip encoding-related errors that we've handled
                if 'encoding' not in error_msg.lower() or 'us-ascii' not in error_msg.lower():
                    feed_result["error"] = {
                        "feed": feed_name,
                        "error": "Feed parsing error",
                        "details": error_msg
                    }
                    return feed_result
        
        feed_result["success"] = True
        
        # Search through entries
        for entry in parsed_feed.entries:
            title = getattr(entry, 'title', '')
            summary = getattr(entry, 'summary', '')
            content = getattr(entry, 'content', '')
            link = getattr(entry, 'link', '')
            
            # Extract text content
            if isinstance(content, list) and content:
                content_text = content[0].get('value', '')
            else:
                content_text = str(content) if content else ''
            
            # Combine all text for searching
            full_text = f"{title} {summary} {content_text}".lower()
            
            # Check if search term is in the content
            if search_term_lower in full_text:
                # Parse publication date
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])
                
                # Don't skip based on date - include all matching articles
                
                # Clean and truncate content
                clean_summary = clean_html_content(summary)
                clean_content = clean_html_content(content_text)
                
                article = {
                    "feed_name": feed_name,
                    "feed_category": category,
                    "title": title,
                    "link": link,
                    "summary": clean_summary[:500] + "..." if len(clean_summary) > 500 else clean_summary,
                    "content": clean_content[:1000] + "..." if len(clean_content) > 1000 else clean_content,
                    "published": pub_date.isoformat() if pub_date else None,
                    "content_hash": get_content_hash(title, clean_content, link)
                }
                
                feed_result["articles"].append(article)
        
    except Exception as e:
        feed_result["error"] = {
            "feed": feed_name,
            "error": "Request failed",
            "details": str(e)
        }
    
    return feed_result

def search_rss_feeds(search_term: str, quiet: bool = False, reload: bool = False, **kwargs) -> Dict[str, Any]:
    """
    Search RSS feeds for articles containing the search term (concurrent processing)
    
    Args:
        search_term: Term to search for
        quiet: Whether to suppress print statements
        reload: Whether to reload cached feeds
        
    Returns:
        Dictionary with search results
    """
    # Clear cache if reload is requested
    if reload:
        if not quiet:
            print("🔄 Clearing RSS cache and reloading feeds...")
        clear_rss_cache()
    
    # Reload feeds in case the configuration file has been updated
    global RSS_FEEDS
    RSS_FEEDS = load_rss_feeds()
    
    if not RSS_FEEDS:
        return {
            "search_term": search_term,
            "feeds_searched": 0,
            "articles_found": 0,
            "articles": [],
            "errors": [{"feed": "Configuration", "error": "No RSS feeds loaded", "details": "Check rss.txt file"}]
        }
    
    search_term_lower = search_term.lower()
    since_date = datetime.now() - timedelta(days=365)  # Look back one year
    
    results = {
        "search_term": search_term,
        "feeds_searched": 0,
        "articles_found": 0,
        "articles": [],
        "errors": []
    }
    
    feeds_to_search = RSS_FEEDS
    total_feeds = len(feeds_to_search)
    
    if not quiet:
        print(f"Starting concurrent search of {total_feeds} RSS feeds...")
    
    # Thread-safe progress tracking
    progress_lock = threading.Lock()
    completed_feeds = 0
    
    def update_progress():
        nonlocal completed_feeds
        with progress_lock:
            completed_feeds += 1
            if not quiet:
                print(f"Completed {completed_feeds}/{total_feeds} feeds", end='\r')
    
    # Use ThreadPoolExecutor for concurrent requests
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Submit all feed search tasks
        future_to_feed = {
            executor.submit(search_single_feed, feed_info, search_term_lower, since_date, reload): feed_info
            for feed_info in feeds_to_search
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_feed):
            feed_result = future.result()
            # print(feed_result["feed_name"])
            
            update_progress()
            
            if feed_result["success"]:
                results["feeds_searched"] += 1
                results["articles"].extend(feed_result["articles"])
                results["articles_found"] += len(feed_result["articles"])
            
            if feed_result["error"]:
                results["errors"].append(feed_result["error"])
    
    if not quiet:
        print()  # New line after progress
    
    # Sort articles by publication date (newest first)
    results["articles"].sort(key=lambda x: x["published"] or "", reverse=True)
    
    return results

def get_available_feeds() -> List[Dict[str, str]]:
    """Get list of available RSS feeds organized by category"""
    # Reload feeds to get latest configuration
    global RSS_FEEDS
    RSS_FEEDS = load_rss_feeds()
    return RSS_FEEDS

def get_feeds_by_category(category: str) -> List[Dict[str, str]]:
    """Get RSS feeds filtered by category"""
    return [feed for feed in get_available_feeds() if feed["category"] == category]

def get_feed_categories() -> List[str]:
    """Get unique list of feed categories"""
    return list(set(feed["category"] for feed in get_available_feeds())) 