#!/usr/bin/env python3

import sqlite3
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import json

logger = logging.getLogger(__name__)

class RSSDatabase:
    """SQLite database for storing RSS articles with deduplication"""
    
    def __init__(self, db_path: str = "data/rss_intelligence.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    last_updated TIMESTAMP,
                    last_error TEXT,
                    error_count INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    description TEXT,
                    content TEXT,
                    published_date TIMESTAMP,
                    author TEXT,
                    tags TEXT,  -- JSON array of tags
                    url_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (feed_id) REFERENCES feeds (id),
                    UNIQUE(url_hash),
                    UNIQUE(content_hash)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_stats (
                    feed_id INTEGER PRIMARY KEY,
                    total_articles INTEGER DEFAULT 0,
                    last_article_date TIMESTAMP,
                    avg_articles_per_day REAL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (feed_id) REFERENCES feeds (id)
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_articles_feed_id ON articles(feed_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_articles_published_date ON articles(published_date)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_articles_url_hash ON articles(url_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_articles_content_hash ON articles(content_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_articles_created_at ON articles(created_at)")
            
            conn.commit()
    
    def _hash_content(self, content: str) -> str:
        """Generate hash for content deduplication"""
        if not content:
            return ""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _hash_url(self, url: str) -> str:
        """Generate hash for URL deduplication"""
        if not url:
            return ""
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    def load_feeds_from_file(self, rss_file: str = "rss.txt") -> int:
        """Load RSS feeds from file into database"""
        rss_path = Path(rss_file)
        if not rss_path.exists():
            logger.error(f"RSS file not found: {rss_file}")
            return 0
        
        feeds_added = 0
        
        with sqlite3.connect(self.db_path) as conn:
            with open(rss_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split('|')
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        url = parts[1].strip()
                        category = parts[2].strip() if len(parts) > 2 else 'uncategorized'
                        
                        if name and url:
                            try:
                                conn.execute("""
                                    INSERT OR IGNORE INTO feeds (name, url, category)
                                    VALUES (?, ?, ?)
                                """, (name, url, category))
                                if conn.total_changes > 0:
                                    feeds_added += 1
                            except sqlite3.Error as e:
                                logger.warning(f"Error adding feed {name}: {e}")
            
            conn.commit()
        
        logger.info(f"Loaded {feeds_added} new feeds from {rss_file}")
        return feeds_added
    
    def get_feeds(self, active_only: bool = True) -> List[Dict]:
        """Get all feeds from database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM feeds"
            if active_only:
                query += " WHERE is_active = 1"
            query += " ORDER BY name"
            
            cursor = conn.execute(query)
            return [dict(row) for row in cursor.fetchall()]
    
    def add_article(self, feed_id: int, article: Dict[str, Any]) -> bool:
        """Add article to database with deduplication"""
        try:
            # Generate hashes for deduplication
            url_hash = self._hash_url(article.get('url', ''))
            content_hash = self._hash_content(
                f"{article.get('title', '')}{article.get('description', '')}{article.get('content', '')}"
            )
            
            # Convert tags to JSON if present
            tags = article.get('tags', [])
            if isinstance(tags, list):
                tags_json = json.dumps(tags)
            else:
                tags_json = None
            
            # Parse published date
            published_date = article.get('published_date')
            if isinstance(published_date, str):
                try:
                    published_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                except ValueError:
                    published_date = None
            
            with sqlite3.connect(self.db_path) as conn:
                try:
                    conn.execute("""
                        INSERT INTO articles (
                            feed_id, title, url, description, content, 
                            published_date, author, tags, url_hash, content_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        feed_id,
                        article.get('title', ''),
                        article.get('url', ''),
                        article.get('description', ''),
                        article.get('content', ''),
                        published_date,
                        article.get('author', ''),
                        tags_json,
                        url_hash,
                        content_hash
                    ))
                    
                    # Update feed stats
                    self._update_feed_stats(conn, feed_id)
                    conn.commit()
                    return True
                    
                except sqlite3.IntegrityError:
                    # Duplicate article (by URL or content hash)
                    return False
                    
        except Exception as e:
            logger.error(f"Error adding article: {e}")
            return False
    
    def _update_feed_stats(self, conn: sqlite3.Connection, feed_id: int):
        """Update statistics for a feed"""
        conn.execute("""
            INSERT OR REPLACE INTO feed_stats (
                feed_id, 
                total_articles, 
                last_article_date,
                updated_at
            )
            SELECT 
                ?, 
                COUNT(*),
                MAX(published_date),
                CURRENT_TIMESTAMP
            FROM articles 
            WHERE feed_id = ?
        """, (feed_id, feed_id))
    
    def update_feed_status(self, feed_id: int, error: str = None):
        """Update feed last updated time and error status"""
        with sqlite3.connect(self.db_path) as conn:
            if error:
                conn.execute("""
                    UPDATE feeds 
                    SET last_updated = CURRENT_TIMESTAMP, 
                        last_error = ?, 
                        error_count = error_count + 1
                    WHERE id = ?
                """, (error, feed_id))
            else:
                conn.execute("""
                    UPDATE feeds 
                    SET last_updated = CURRENT_TIMESTAMP, 
                        last_error = NULL, 
                        error_count = 0
                    WHERE id = ?
                """, (feed_id,))
            conn.commit()
    
    def search_articles(self, search_term: str, limit: int = 100, 
                       category: str = None, days_back: int = None) -> List[Dict]:
        """Search articles by term"""
        query = """
            SELECT a.*, f.name as feed_name, f.category, f.url as feed_url
            FROM articles a
            JOIN feeds f ON a.feed_id = f.id
            WHERE (a.title LIKE ? OR a.description LIKE ? OR a.content LIKE ?)
        """
        params = [f"%{search_term}%", f"%{search_term}%", f"%{search_term}%"]
        
        if category:
            query += " AND f.category = ?"
            params.append(category)
        
        if days_back:
            query += " AND a.published_date >= datetime('now', '-{} days')".format(days_back)
        
        query += " ORDER BY a.published_date DESC LIMIT ?"
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get feed counts
            feed_stats = conn.execute("""
                SELECT 
                    COUNT(*) as total_feeds,
                    COUNT(CASE WHEN is_active = 1 THEN 1 END) as active_feeds,
                    COUNT(CASE WHEN last_error IS NOT NULL THEN 1 END) as feeds_with_errors
                FROM feeds
            """).fetchone()
            
            # Get article counts
            article_stats = conn.execute("""
                SELECT 
                    COUNT(*) as total_articles,
                    COUNT(DISTINCT feed_id) as feeds_with_articles,
                    MIN(published_date) as oldest_article,
                    MAX(published_date) as newest_article
                FROM articles
            """).fetchone()
            
            # Get category breakdown
            category_stats = conn.execute("""
                SELECT category, COUNT(*) as count
                FROM feeds
                WHERE is_active = 1
                GROUP BY category
                ORDER BY count DESC
            """).fetchall()
            
            return {
                'feeds': dict(feed_stats),
                'articles': dict(article_stats),
                'categories': [dict(row) for row in category_stats]
            }
    
    def cleanup_old_articles(self, days_to_keep: int = 365) -> int:
        """Remove articles older than specified days"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                DELETE FROM articles 
                WHERE published_date < datetime('now', '-{} days')
            """.format(days_to_keep))
            
            deleted_count = cursor.rowcount
            
            # Update feed stats after cleanup
            for feed in self.get_feeds():
                self._update_feed_stats(conn, feed['id'])
            
            conn.commit()
            return deleted_count
    
    def close(self):
        """Close database connection (placeholder for future connection pooling)"""
        pass 