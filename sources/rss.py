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
import sys
import os

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))
from models.rss_database import RSSDatabase

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

# RSS database configuration
RSS_DB_PATH = "data/rss_intelligence.db"
FEED_UPDATE_INTERVAL = 3600  # 1 hour in seconds

def get_rss_database() -> RSSDatabase:
    """Get RSS database instance"""
    return RSSDatabase(RSS_DB_PATH)

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

def parse_feed_with_encoding_fallback(feed_url: str) -> Any:
    """Parse RSS feed with encoding fallback to handle character encoding issues"""
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
                # Try latin-1 if UTF-8 fails
                try:
                    content_str = content.decode('latin-1')
                except UnicodeDecodeError:
                    # Last resort: ignore errors
                    content_str = content.decode('utf-8', errors='ignore')
            
            # Parse the corrected content
            parsed_feed = feedparser.parse(content_str)
        
        return parsed_feed
        
    except Exception as e:
        # Return a minimal feed object with error info
        return feedparser.FeedParserDict({
            'bozo': True,
            'bozo_exception': e,
            'entries': []
        })

def is_feed_update_needed(db: RSSDatabase, feed_id: int) -> bool:
    """Check if a feed needs to be updated based on last update time"""
    feeds = db.get_feeds()
    for feed in feeds:
        if feed['id'] == feed_id:
            if not feed['last_updated']:
                return True
            
            try:
                # Parse the timestamp from database (SQLite format)
                last_updated_str = feed['last_updated']
                if 'T' in last_updated_str:
                    # ISO format with timezone
                    last_updated = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
                else:
                    # SQLite CURRENT_TIMESTAMP format (UTC)
                    last_updated = datetime.strptime(last_updated_str, '%Y-%m-%d %H:%M:%S')
                
                time_since_update = datetime.utcnow() - last_updated
                return time_since_update.total_seconds() > FEED_UPDATE_INTERVAL
            except (ValueError, TypeError) as e:
                # If we can't parse the date, assume it needs updating
                return True
    
    return True

def update_feed_articles(db: RSSDatabase, feed_info: Dict[str, str], feed_id: int) -> None:
    """Update articles for a specific feed by fetching latest content"""
    try:
        parsed_feed = parse_feed_with_encoding_fallback(feed_info["url"])
        
        if hasattr(parsed_feed, 'bozo') and parsed_feed.bozo:
            if not parsed_feed.entries and parsed_feed.bozo_exception:
                error_msg = str(parsed_feed.bozo_exception)
                if 'encoding' not in error_msg.lower():
                    db.update_feed_status(feed_id, error_msg)
                    return
        
        # Process each entry and add to database
        articles_added = 0
        for entry in parsed_feed.entries:
            title = getattr(entry, 'title', '')
            summary = getattr(entry, 'summary', '')
            content = getattr(entry, 'content', '')
            link = getattr(entry, 'link', '')
            author = getattr(entry, 'author', '')
            
            # Extract text content
            if isinstance(content, list) and content:
                content_text = content[0].get('value', '')
            else:
                content_text = str(content) if content else ''
            
            # Parse publication date
            pub_date = None
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                pub_date = datetime(*entry.published_parsed[:6])
            elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                pub_date = datetime(*entry.updated_parsed[:6])
            
            # Clean content
            clean_summary = clean_html_content(summary)
            clean_content = clean_html_content(content_text)
            
            # Create article object
            article = {
                'title': title,
                'url': link,
                'description': clean_summary,
                'content': clean_content,
                'published_date': pub_date,
                'author': author,
                'tags': []  # Could extract from entry if available
            }
            
            # Add to database (will handle deduplication)
            if db.add_article(feed_id, article):
                articles_added += 1
        
        # Update feed status
        db.update_feed_status(feed_id)
        
    except Exception as e:
        db.update_feed_status(feed_id, str(e))

def search_rss_feeds(search_term: str, quiet: bool = False, reload: bool = False, **kwargs) -> Dict[str, Any]:
    """
    Search RSS feeds using SQLite database with intelligent caching
    
    Args:
        search_term: Search term to look for
        quiet: If True, suppress progress output  
        reload: Force reload feeds from source
        
    Returns:
        Dictionary with search results
    """
    db = get_rss_database()
    
    if not RSS_FEEDS:
        return {
            "source": "rss",
            "search_term": search_term,
            "total_results": 0,
            "results": [],
            "errors": ["No RSS feeds configured in rss.txt"]
        }
    
    # Initialize database with feeds from config file if needed
    existing_feeds = {f['url']: f for f in db.get_feeds()}
    
    if not existing_feeds:
        feeds_added = db.load_feeds_from_file("rss.txt")
    
    # Get all feeds from database
    all_feeds = db.get_feeds()
    
    # Only update feeds if explicitly requested or if they're stale
    if reload:
        # Force update all feeds when reload flag is used
        feeds_to_update = []
        if not quiet:
            print(f"🔄 Reload requested - updating all {len(all_feeds)} RSS feeds...")
        
        for feed in all_feeds:
            # Find corresponding config entry
            feed_config = None
            for config_feed in RSS_FEEDS:
                if config_feed['url'] == feed['url']:
                    feed_config = config_feed
                    break
            
            if feed_config:
                feeds_to_update.append((feed, feed_config))
        
        # Update feeds that need refreshing
        if feeds_to_update:
            max_workers = min(len(feeds_to_update), 10)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_feed = {
                    executor.submit(update_feed_articles, db, feed_config, feed['id']): (feed, feed_config)
                    for feed, feed_config in feeds_to_update
                }
                
                for future in as_completed(future_to_feed):
                    feed, feed_config = future_to_feed[future]
                    try:
                        future.result()
                        if not quiet:
                            print(f"  ✓ Updated {feed['name']}")
                    except Exception as e:
                        if not quiet:
                            print(f"  ✗ Failed to update {feed['name']}: {e}")
    else:
        # Check which feeds need updating based on age (only if not explicitly skipping updates)
        feeds_to_update = []
        stale_feeds = 0
        
        for feed in all_feeds:
            if is_feed_update_needed(db, feed['id']):
                stale_feeds += 1
                # Find corresponding config entry
                feed_config = None
                for config_feed in RSS_FEEDS:
                    if config_feed['url'] == feed['url']:
                        feed_config = config_feed
                        break
                
                if feed_config:
                    feeds_to_update.append((feed, feed_config))
        
        # Update only stale feeds (silently if quiet=True)
        if feeds_to_update:
            max_workers = min(len(feeds_to_update), 5)  # Reduced workers for background updates
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_feed = {
                    executor.submit(update_feed_articles, db, feed_config, feed['id']): (feed, feed_config)
                    for feed, feed_config in feeds_to_update
                }
                
                for future in as_completed(future_to_feed):
                    feed, feed_config = future_to_feed[future]
                    try:
                        future.result()
                    except Exception as e:
                        pass
    
    # Search articles in database (focus on article content, not feed names)
    articles = db.search_articles(search_term, limit=1000)
    
    # Format results to match expected structure
    formatted_articles = []
    for article in articles:
        formatted_article = {
            "feed_name": article['feed_name'],
            "feed_category": article['category'] or 'uncategorized',
            "title": article['title'],
            "link": article['url'],
            "summary": article['description'],
            "content": article['content'],
            "published": article['published_date'],
            "content_hash": get_content_hash(article['title'], article['content'], article['url'])
        }
        formatted_articles.append(formatted_article)
    

    
    return {
        "source": "rss",
        "search_term": search_term,
        "total_results": len(formatted_articles),
        "results": formatted_articles,
        "errors": []
    }

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