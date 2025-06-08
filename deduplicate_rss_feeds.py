#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from collections import defaultdict, Counter
from urllib.parse import urlparse
import re
from typing import Dict, List, Tuple, Set

class RSSFeedDeduplicator:
    """Tool to deduplicate RSS feeds based on URL"""
    
    def __init__(self, rss_file: str = "rss.txt"):
        self.rss_file = Path(rss_file)
        self.feeds = []
        self.duplicates = defaultdict(list)
        self.stats = {}
        
    def load_feeds(self) -> bool:
        """Load RSS feeds from file"""
        if not self.rss_file.exists():
            print(f"❌ RSS file not found: {self.rss_file}")
            return False
            
        self.feeds = []
        line_num = 0
        
        try:
            with open(self.rss_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse the feed format: name|url|category
                    parts = line.split('|')
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        url = parts[1].strip()
                        category = parts[2].strip() if len(parts) > 2 else 'uncategorized'
                        
                        if name and url:
                            self.feeds.append({
                                'name': name,
                                'url': url,
                                'category': category,
                                'line_num': line_num,
                                'original_line': line
                            })
                    else:
                        print(f"⚠️  Warning: Invalid format in {self.rss_file} line {line_num}: {line}")
                        
        except Exception as e:
            print(f"❌ Error reading {self.rss_file}: {e}")
            return False
            
        print(f"✅ Loaded {len(self.feeds)} RSS feeds from {self.rss_file}")
        return True
    
    def analyze_duplicates(self):
        """Analyze and categorize duplicate URLs"""
        url_to_feeds = defaultdict(list)
        
        # Group feeds by URL
        for feed in self.feeds:
            url_to_feeds[feed['url']].append(feed)
        
        # Find duplicates
        self.duplicates = {}
        unique_feeds = {}
        
        for url, feeds_list in url_to_feeds.items():
            if len(feeds_list) > 1:
                self.duplicates[url] = feeds_list
            else:
                unique_feeds[url] = feeds_list[0]
        
        # Calculate statistics
        total_feeds = len(self.feeds)
        duplicate_urls = len(self.duplicates)
        total_duplicate_entries = sum(len(feeds) for feeds in self.duplicates.values())
        urls_after_dedup = len(url_to_feeds)
        feeds_to_remove = total_duplicate_entries - duplicate_urls
        
        self.stats = {
            'total_feeds': total_feeds,
            'unique_urls': len(url_to_feeds),
            'duplicate_urls': duplicate_urls,
            'total_duplicate_entries': total_duplicate_entries,
            'feeds_to_remove': feeds_to_remove,
            'feeds_after_dedup': total_feeds - feeds_to_remove
        }
        
        return unique_feeds
    
    def print_summary(self):
        """Print deduplication summary"""
        print("\n" + "=" * 70)
        print("📊 RSS FEED DEDUPLICATION ANALYSIS")
        print("=" * 70)
        print(f"📝 Total feeds loaded: {self.stats['total_feeds']}")
        print(f"🔗 Unique URLs: {self.stats['unique_urls']}")
        print(f"🔄 Duplicate URLs: {self.stats['duplicate_urls']}")
        print(f"📋 Total duplicate entries: {self.stats['total_duplicate_entries']}")
        print(f"🗑️  Feeds to remove: {self.stats['feeds_to_remove']}")
        print(f"✨ Feeds after deduplication: {self.stats['feeds_after_dedup']}")
        
        if self.stats['feeds_to_remove'] > 0:
            reduction = (self.stats['feeds_to_remove'] / self.stats['total_feeds']) * 100
            print(f"📉 Reduction: {reduction:.1f}%")
    
    def print_duplicates(self, detailed: bool = False, limit: int = None):
        """Print duplicate URLs and their associated feeds"""
        if not self.duplicates:
            print("\n✅ No duplicate URLs found!")
            return
            
        print(f"\n🔄 Found {len(self.duplicates)} URLs with duplicates:")
        print("-" * 70)
        
        sorted_duplicates = sorted(self.duplicates.items(), key=lambda x: len(x[1]), reverse=True)
        
        if limit:
            sorted_duplicates = sorted_duplicates[:limit]
        
        for i, (url, feeds_list) in enumerate(sorted_duplicates, 1):
            print(f"\n{i}. URL: {url}")
            print(f"   Duplicate count: {len(feeds_list)}")
            
            if detailed:
                print("   Feeds:")
                for j, feed in enumerate(feeds_list, 1):
                    print(f"     {j}. {feed['name']} [{feed['category']}] (line {feed['line_num']})")
            else:
                # Show just the names
                names = [f"'{feed['name']}'" for feed in feeds_list]
                print(f"   Feeds: {', '.join(names)}")
    
    def suggest_deduplication_strategy(self, url: str, feeds_list: List[Dict]) -> Dict:
        """Suggest which feed to keep based on various criteria"""
        if len(feeds_list) <= 1:
            return feeds_list[0] if feeds_list else None
        
        # Scoring criteria
        scores = []
        
        for feed in feeds_list:
            score = 0
            name = feed['name'].lower()
            
            # Prefer shorter, more generic names
            if 'official' in name or 'blog' in name:
                score += 10
            
            # Prefer feeds with better categories
            category_scores = {
                'threat_intelligence': 15,
                'security_research': 12,
                'cybersecurity': 10,
                'government': 8,
                'intelligence': 7,
                'general_security': 5
            }
            score += category_scores.get(feed['category'], 0)
            
            # Penalize very specific or branded names
            if ' - ' in feed['name']:  # Likely a sub-section
                score -= 5
            
            # Prefer shorter names (less specific)
            score -= len(feed['name']) * 0.1
            
            scores.append((score, feed))
        
        # Sort by score (highest first)
        scores.sort(key=lambda x: x[0], reverse=True)
        
        return {
            'keep': scores[0][1],
            'remove': [item[1] for item in scores[1:]],
            'reasoning': f"Kept '{scores[0][1]['name']}' (score: {scores[0][0]:.1f})"
        }
    
    def deduplicate_interactive(self):
        """Interactive deduplication with user choices"""
        if not self.duplicates:
            print("✅ No duplicates to process!")
            return
        
        print(f"\n🔧 Interactive deduplication of {len(self.duplicates)} duplicate URLs")
        print("For each duplicate URL, choose which feed to keep.\n")
        
        decisions = {}
        
        for i, (url, feeds_list) in enumerate(self.duplicates.items(), 1):
            print(f"\n--- Duplicate {i}/{len(self.duplicates)} ---")
            print(f"URL: {url}")
            print("Feeds:")
            
            for j, feed in enumerate(feeds_list, 1):
                print(f"  {j}. {feed['name']} [{feed['category']}]")
            
            # Get suggestion
            suggestion = self.suggest_deduplication_strategy(url, feeds_list)
            suggested_idx = feeds_list.index(suggestion['keep']) + 1
            print(f"\n💡 Suggestion: Keep #{suggested_idx} - {suggestion['reasoning']}")
            
            while True:
                try:
                    choice = input(f"Which feed to keep? (1-{len(feeds_list)}, default={suggested_idx}): ").strip()
                    
                    if not choice:
                        choice = suggested_idx
                    else:
                        choice = int(choice)
                    
                    if 1 <= choice <= len(feeds_list):
                        decisions[url] = {
                            'keep': feeds_list[choice - 1],
                            'remove': feeds_list[:choice-1] + feeds_list[choice:]
                        }
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(feeds_list)}")
                        
                except (ValueError, KeyboardInterrupt):
                    if KeyboardInterrupt:
                        print("\n\n⚠️  Deduplication cancelled by user")
                        return None
                    print("Please enter a valid number")
        
        return decisions
    
    def deduplicate_automatic(self, strategy: str = 'smart') -> Dict:
        """Automatic deduplication using specified strategy"""
        if not self.duplicates:
            return {}
        
        decisions = {}
        
        for url, feeds_list in self.duplicates.items():
            if strategy == 'smart':
                suggestion = self.suggest_deduplication_strategy(url, feeds_list)
                decisions[url] = {
                    'keep': suggestion['keep'],
                    'remove': suggestion['remove']
                }
            elif strategy == 'first':
                decisions[url] = {
                    'keep': feeds_list[0],
                    'remove': feeds_list[1:]
                }
            elif strategy == 'shortest':
                shortest = min(feeds_list, key=lambda x: len(x['name']))
                others = [f for f in feeds_list if f != shortest]
                decisions[url] = {
                    'keep': shortest,
                    'remove': others
                }
        
        return decisions
    
    def apply_deduplication(self, decisions: Dict, output_file: str = None, dry_run: bool = False):
        """Apply deduplication decisions to create a new RSS file"""
        if not decisions:
            print("❌ No deduplication decisions to apply")
            return False
        
        # Collect feeds to remove
        feeds_to_remove = set()
        for url, decision in decisions.items():
            for feed in decision['remove']:
                feeds_to_remove.add(feed['line_num'])
        
        # Prepare output
        output_lines = []
        removed_count = 0
        
        try:
            with open(self.rss_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num in feeds_to_remove:
                        removed_count += 1
                        if dry_run:
                            output_lines.append(f"# REMOVED: {line.rstrip()}")
                    else:
                        output_lines.append(line.rstrip())
        
        except Exception as e:
            print(f"❌ Error reading original file: {e}")
            return False
        
        # Determine output file
        if not output_file:
            if dry_run:
                output_file = f"{self.rss_file.stem}_deduplicated_preview.txt"
            else:
                output_file = f"{self.rss_file.stem}_deduplicated.txt"
        
        output_path = Path(output_file)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines) + '\n')
            
            action = "Preview created" if dry_run else "Deduplicated file created"
            print(f"✅ {action}: {output_path}")
            print(f"📊 Removed {removed_count} duplicate feeds")
            print(f"📊 Remaining feeds: {len(self.feeds) - removed_count}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error writing output file: {e}")
            return False
    
    def print_decisions_summary(self, decisions: Dict):
        """Print summary of deduplication decisions"""
        if not decisions:
            return
        
        print(f"\n📋 Deduplication decisions for {len(decisions)} URLs:")
        print("-" * 50)
        
        for url, decision in decisions.items():
            kept_feed = decision['keep']
            removed_feeds = decision['remove']
            
            print(f"\nURL: {url}")
            print(f"  ✅ KEEP: {kept_feed['name']} [{kept_feed['category']}]")
            for feed in removed_feeds:
                print(f"  ❌ REMOVE: {feed['name']} [{feed['category']}]")

def main():
    parser = argparse.ArgumentParser(
        description="Deduplicate RSS feeds based on URL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --analyze                           # Show duplicate analysis
  %(prog)s --list-duplicates --detailed        # Show detailed duplicate list
  %(prog)s --deduplicate --interactive         # Interactive deduplication
  %(prog)s --deduplicate --strategy smart      # Automatic smart deduplication
  %(prog)s --deduplicate --strategy first      # Keep first occurrence
  %(prog)s --dry-run --strategy smart          # Preview deduplication
        """
    )
    
    parser.add_argument(
        "--rss-file",
        default="rss.txt",
        help="RSS feeds file to process (default: rss.txt)"
    )
    
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze and show duplicate statistics"
    )
    
    parser.add_argument(
        "--list-duplicates",
        action="store_true",
        help="List all duplicate URLs"
    )
    
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed information for duplicates"
    )
    
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of duplicates shown"
    )
    
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        help="Perform deduplication"
    )
    
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Use interactive mode for deduplication"
    )
    
    parser.add_argument(
        "--strategy",
        choices=['smart', 'first', 'shortest'],
        default='smart',
        help="Automatic deduplication strategy (default: smart)"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for deduplicated feeds"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying files"
    )
    
    args = parser.parse_args()
    
    # Create deduplicator
    deduplicator = RSSFeedDeduplicator(args.rss_file)
    
    # Load feeds
    if not deduplicator.load_feeds():
        sys.exit(1)
    
    # Analyze duplicates
    unique_feeds = deduplicator.analyze_duplicates()
    
    # Show analysis if requested
    if args.analyze or not any([args.list_duplicates, args.deduplicate]):
        deduplicator.print_summary()
    
    # List duplicates if requested
    if args.list_duplicates:
        deduplicator.print_duplicates(detailed=args.detailed, limit=args.limit)
    
    # Perform deduplication if requested
    if args.deduplicate:
        if args.interactive:
            decisions = deduplicator.deduplicate_interactive()
        else:
            decisions = deduplicator.deduplicate_automatic(args.strategy)
            
        if decisions:
            deduplicator.print_decisions_summary(decisions)
            deduplicator.apply_deduplication(decisions, args.output, args.dry_run)
    
    # If no specific action requested, show helpful message
    if not any([args.analyze, args.list_duplicates, args.deduplicate]):
        print(f"\n💡 Use --analyze to see duplicate statistics")
        print(f"💡 Use --list-duplicates to see duplicate URLs")
        print(f"💡 Use --deduplicate to clean up duplicates")

if __name__ == "__main__":
    main() 