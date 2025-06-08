#!/usr/bin/env python3

import argparse
import asyncio
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import feedparser
import httpx
from bs4 import BeautifulSoup

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

from models.rss_database import RSSDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RSSCollector:
    """Collect RSS articles and store them in database"""
    
    def __init__(self, db_path: str = "data/rss_intelligence.db", concurrent_feeds: int = 10):
        self.db = RSSDatabase(db_path)
        self.concurrent_feeds = concurrent_feeds
        self.session = None
        self.stats = {
            'feeds_processed': 0,
            'feeds_successful': 0,
            'feeds_failed': 0,
            'articles_found': 0,
            'articles_new': 0,
            'articles_duplicate': 0
        }
    
    async def init_session(self):
        """Initialize HTTP session"""
        timeout = httpx.Timeout(30.0, connect=10.0)
        self.session = httpx.AsyncClient(
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; RSS Intelligence Collector/1.0)'
            },
            follow_redirects=True
        )
    
    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.aclose()
    
    async def fetch_feed(self, feed: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch and parse a single RSS feed"""
        feed_id = feed['id']
        feed_url = feed['url']
        feed_name = feed['name']
        
        try:
            logger.info(f"Fetching feed: {feed_name} ({feed_url})")
            
            # Fetch RSS content
            response = await self.session.get(feed_url)
            response.raise_for_status()
            
            # Parse RSS content
            feed_data = feedparser.parse(response.content)
            
            if feed_data.bozo and hasattr(feed_data, 'bozo_exception'):
                logger.warning(f"Feed parsing warning for {feed_name}: {feed_data.bozo_exception}")
            
            articles_found = 0
            articles_new = 0
            articles_duplicate = 0
            
            # Process entries
            for entry in feed_data.entries:
                articles_found += 1
                
                # Extract article data
                article_data = self._extract_article_data(entry, feed_data.feed)
                
                # Add to database
                if self.db.add_article(feed_id, article_data):
                    articles_new += 1
                else:
                    articles_duplicate += 1
            
            # Update feed status (success)
            self.db.update_feed_status(feed_id)
            
            result = {
                'status': 'success',
                'feed_id': feed_id,
                'feed_name': feed_name,
                'articles_found': articles_found,
                'articles_new': articles_new,
                'articles_duplicate': articles_duplicate,
                'error': None
            }
            
            logger.info(f"✅ {feed_name}: {articles_found} found, {articles_new} new, {articles_duplicate} duplicates")
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Failed to fetch {feed_name}: {error_msg}")
            
            # Update feed status (error)
            self.db.update_feed_status(feed_id, error_msg)
            
            return {
                'status': 'error',
                'feed_id': feed_id,
                'feed_name': feed_name,
                'articles_found': 0,
                'articles_new': 0,
                'articles_duplicate': 0,
                'error': error_msg
            }
    
    def _extract_article_data(self, entry: Any, feed_info: Any) -> Dict[str, Any]:
        """Extract article data from RSS entry"""
        # Get title
        title = getattr(entry, 'title', '')
        
        # Get URL
        url = getattr(entry, 'link', '')
        
        # Get description/summary
        description = ''
        if hasattr(entry, 'summary'):
            description = entry.summary
        elif hasattr(entry, 'description'):
            description = entry.description
        
        # Clean HTML from description
        if description:
            soup = BeautifulSoup(description, 'html.parser')
            description = soup.get_text(strip=True)
        
        # Get content
        content = ''
        if hasattr(entry, 'content') and entry.content:
            # Take the first content item
            content_item = entry.content[0] if isinstance(entry.content, list) else entry.content
            if hasattr(content_item, 'value'):
                content = content_item.value
        
        # Clean HTML from content
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text(strip=True)
        
        # Get published date
        published_date = None
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            try:
                published_date = datetime(*entry.published_parsed[:6])
            except (TypeError, ValueError):
                pass
        
        if not published_date and hasattr(entry, 'updated_parsed') and entry.updated_parsed:
            try:
                published_date = datetime(*entry.updated_parsed[:6])
            except (TypeError, ValueError):
                pass
        
        # Get author
        author = ''
        if hasattr(entry, 'author'):
            author = entry.author
        elif hasattr(entry, 'authors') and entry.authors:
            author = ', '.join([a.get('name', a.get('email', str(a))) for a in entry.authors])
        
        # Get tags
        tags = []
        if hasattr(entry, 'tags') and entry.tags:
            tags = [tag.get('term', str(tag)) for tag in entry.tags]
        
        return {
            'title': title,
            'url': url,
            'description': description,
            'content': content,
            'published_date': published_date,
            'author': author,
            'tags': tags
        }
    
    async def collect_feeds(self, limit: int = None, category: str = None, 
                           skip_recent: bool = True, hours_threshold: int = 6) -> Dict[str, Any]:
        """Collect articles from all feeds"""
        logger.info("Starting RSS collection...")
        
        # Initialize session
        await self.init_session()
        
        try:
            # Get feeds from database
            all_feeds = self.db.get_feeds(active_only=True)
            
            # Filter by category if specified
            if category:
                all_feeds = [f for f in all_feeds if f['category'] == category]
            
            # Skip recently updated feeds if requested
            if skip_recent:
                cutoff_time = datetime.now() - timedelta(hours=hours_threshold)
                feeds_to_process = []
                
                for feed in all_feeds:
                    if feed['last_updated']:
                        try:
                            last_updated = datetime.fromisoformat(feed['last_updated'].replace('Z', '+00:00'))
                            if last_updated.replace(tzinfo=None) < cutoff_time:
                                feeds_to_process.append(feed)
                            else:
                                logger.debug(f"Skipping recently updated feed: {feed['name']}")
                        except ValueError:
                            feeds_to_process.append(feed)
                    else:
                        feeds_to_process.append(feed)
            else:
                feeds_to_process = all_feeds
            
            # Apply limit if specified
            if limit:
                feeds_to_process = feeds_to_process[:limit]
            
            logger.info(f"Processing {len(feeds_to_process)} feeds (out of {len(all_feeds)} total)")
            
            # Reset stats
            self.stats = {
                'feeds_processed': 0,
                'feeds_successful': 0,
                'feeds_failed': 0,
                'articles_found': 0,
                'articles_new': 0,
                'articles_duplicate': 0
            }
            
            # Process feeds concurrently
            semaphore = asyncio.Semaphore(self.concurrent_feeds)
            
            async def process_feed_with_semaphore(feed):
                async with semaphore:
                    return await self.fetch_feed(feed)
            
            # Create tasks
            tasks = [process_feed_with_semaphore(feed) for feed in feeds_to_process]
            
            # Process tasks and collect results
            results = []
            for task in asyncio.as_completed(tasks):
                result = await task
                results.append(result)
                
                # Update stats
                self.stats['feeds_processed'] += 1
                if result['status'] == 'success':
                    self.stats['feeds_successful'] += 1
                else:
                    self.stats['feeds_failed'] += 1
                
                self.stats['articles_found'] += result['articles_found']
                self.stats['articles_new'] += result['articles_new']
                self.stats['articles_duplicate'] += result['articles_duplicate']
                
                # Show progress
                progress = (self.stats['feeds_processed'] / len(feeds_to_process)) * 100
                logger.info(f"Progress: {self.stats['feeds_processed']}/{len(feeds_to_process)} ({progress:.1f}%)")
            
            return {
                'status': 'completed',
                'stats': self.stats,
                'results': results
            }
            
        finally:
            await self.close_session()
    
    def initialize_database(self, rss_file: str = "rss.txt"):
        """Initialize database with feeds from RSS file"""
        logger.info("Initializing database with RSS feeds...")
        feeds_added = self.db.load_feeds_from_file(rss_file)
        logger.info(f"Added {feeds_added} new feeds to database")
        return feeds_added
    
    def print_stats(self):
        """Print collection statistics"""
        print("\n" + "=" * 70)
        print("📊 RSS COLLECTION STATISTICS")
        print("=" * 70)
        print(f"📡 Feeds processed: {self.stats['feeds_processed']}")
        print(f"✅ Successful: {self.stats['feeds_successful']}")
        print(f"❌ Failed: {self.stats['feeds_failed']}")
        print(f"📰 Articles found: {self.stats['articles_found']}")
        print(f"🆕 New articles: {self.stats['articles_new']}")
        print(f"🔄 Duplicates: {self.stats['articles_duplicate']}")
        
        if self.stats['feeds_processed'] > 0:
            success_rate = (self.stats['feeds_successful'] / self.stats['feeds_processed']) * 100
            print(f"📈 Success rate: {success_rate:.1f}%")
        
        if self.stats['articles_found'] > 0:
            new_rate = (self.stats['articles_new'] / self.stats['articles_found']) * 100
            print(f"🆕 New article rate: {new_rate:.1f}%")
    
    def print_database_stats(self):
        """Print database statistics"""
        stats = self.db.get_database_stats()
        
        print("\n" + "=" * 70)
        print("🗄️  DATABASE STATISTICS")
        print("=" * 70)
        print(f"📡 Total feeds: {stats['feeds']['total_feeds']}")
        print(f"✅ Active feeds: {stats['feeds']['active_feeds']}")
        print(f"❌ Feeds with errors: {stats['feeds']['feeds_with_errors']}")
        print(f"📰 Total articles: {stats['articles']['total_articles']}")
        print(f"📡 Feeds with articles: {stats['articles']['feeds_with_articles']}")
        
        if stats['articles']['oldest_article']:
            print(f"📅 Oldest article: {stats['articles']['oldest_article']}")
        if stats['articles']['newest_article']:
            print(f"📅 Newest article: {stats['articles']['newest_article']}")
        
        print("\n📊 Categories:")
        for cat in stats['categories']:
            print(f"  {cat['category']}: {cat['count']} feeds")

async def main():
    parser = argparse.ArgumentParser(
        description="Collect RSS articles and store in database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --init                              # Initialize database with feeds
  %(prog)s --collect                           # Collect from all feeds
  %(prog)s --collect --limit 10                # Collect from first 10 feeds
  %(prog)s --collect --category cybersecurity  # Collect only cybersecurity feeds
  %(prog)s --collect --force                   # Force update all feeds
  %(prog)s --stats                             # Show database statistics
  %(prog)s --cleanup --days 180                # Remove articles older than 180 days
        """
    )
    
    parser.add_argument(
        "--db-path",
        default="data/rss_intelligence.db",
        help="Path to SQLite database (default: data/rss_intelligence.db)"
    )
    
    parser.add_argument(
        "--rss-file",
        default="rss.txt",
        help="RSS feeds file (default: rss.txt)"
    )
    
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize database with feeds from RSS file"
    )
    
    parser.add_argument(
        "--collect",
        action="store_true",
        help="Collect articles from RSS feeds"
    )
    
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of feeds to process"
    )
    
    parser.add_argument(
        "--category",
        help="Only process feeds from specific category"
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force collection even from recently updated feeds"
    )
    
    parser.add_argument(
        "--concurrent",
        type=int,
        default=10,
        help="Number of concurrent feed fetches (default: 10)"
    )
    
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show database statistics"
    )
    
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up old articles"
    )
    
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Days to keep articles for cleanup (default: 365)"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output verbosity"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Create collector
    collector = RSSCollector(args.db_path, args.concurrent)
    
    # Initialize database if requested
    if args.init:
        collector.initialize_database(args.rss_file)
    
    # Collect articles if requested
    if args.collect:
        print("🚀 Starting RSS article collection...")
        start_time = time.time()
        
        result = await collector.collect_feeds(
            limit=args.limit,
            category=args.category,
            skip_recent=not args.force,
            hours_threshold=6
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        collector.print_stats()
        print(f"\n⏱️  Collection completed in {duration:.1f} seconds")
    
    # Show database statistics if requested
    if args.stats:
        collector.print_database_stats()
    
    # Cleanup old articles if requested
    if args.cleanup:
        print(f"🧹 Cleaning up articles older than {args.days} days...")
        deleted_count = collector.db.cleanup_old_articles(args.days)
        print(f"🗑️  Removed {deleted_count} old articles")
    
    # If no action specified, show help
    if not any([args.init, args.collect, args.stats, args.cleanup]):
        print("💡 Use --init to initialize database")
        print("💡 Use --collect to fetch articles")
        print("💡 Use --stats to see database statistics")
        print("💡 Use --help for more options")

if __name__ == "__main__":
    asyncio.run(main()) 