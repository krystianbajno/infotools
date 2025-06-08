#!/usr/bin/env python3

import logging
from typing import Dict, List, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Add current directory to path for imports
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from utils.search_parser import parse_search_term, SearchOperator
from services.search_service import search_single_source

logger = logging.getLogger(__name__)

class SearchOrchestrator:
    """Orchestrates searches across sources with logical operator support"""
    
    def __init__(self):
        self.result_cache = {}
    
    def search_with_logical_operators(self, search_term: str, sources: List[str] = None, 
                                    quiet: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Execute search with logical operator support
        
        Args:
            search_term: Search term with optional logical operators (|, &)
            sources: List of source names to search
            quiet: Whether to suppress progress messages
            **kwargs: Additional search parameters
            
        Returns:
            Combined search results
        """
        # Parse the search term
        try:
            search_query = parse_search_term(search_term)
        except ValueError as e:
            return {
                'status': 'error',
                'error': str(e),
                'search_term': search_term
            }
        
        if not quiet:
            if search_query.is_or():
                print(f"🔍 OR Search: {search_query}")
            elif search_query.is_and():
                print(f"🔍 AND Search: {search_query}")
            else:
                print(f"🔍 Simple Search: {search_query}")
        
        if search_query.is_simple():
            # Simple search - just pass through to original search
            return self._execute_simple_search(search_query.terms[0], sources, quiet, **kwargs)
        
        elif search_query.is_or():
            # OR search - search each term separately and combine results
            return self._execute_or_search(search_query.terms, sources, quiet, **kwargs)
        
        elif search_query.is_and():
            # AND search - search each term and find intersection
            return self._execute_and_search(search_query.terms, sources, quiet, **kwargs)
        
        return {
            'status': 'error',
            'error': 'Unknown search operator',
            'search_term': search_term
        }
    
    def _execute_simple_search(self, search_term: str, sources: List[str], 
                             quiet: bool, **kwargs) -> Dict[str, Any]:
        """Execute a simple search without logical operators"""
        from services.search_service import search_all_sources
        return search_all_sources(search_term, sources, quiet, **kwargs)
    
    def _execute_or_search(self, terms: List[str], sources: List[str], 
                          quiet: bool, **kwargs) -> Dict[str, Any]:
        """Execute OR search - combine results from all terms"""
        if not quiet:
            print(f"📝 Searching {len(terms)} terms: {', '.join(terms)}")
        
        all_results = {}
        combined_sources_searched = set()
        
        # Search each term separately
        for i, term in enumerate(terms):
            if not quiet:
                print(f"  🔍 Term {i+1}/{len(terms)}: '{term}'")
            
            term_results = self._execute_simple_search(term, sources, True, **kwargs)  # quiet=True for individual searches
            
            if 'error' in term_results:
                continue
            
            # Track which sources returned results
            combined_sources_searched.update(term_results.get('sources_searched', []))
            
            # Combine results from each source
            for source_name, source_result in term_results.get('results', {}).items():
                if source_result['status'] == 'success' and source_result.get('results'):
                    if source_name not in all_results:
                        all_results[source_name] = {
                            'status': 'success',
                            'source': source_name,
                            'results': [],
                            'count': 0
                        }
                        # Copy other metadata
                        for key, value in source_result.items():
                            if key not in ['results', 'count']:
                                all_results[source_name][key] = value
                    
                    # Add results with deduplication
                    existing_results = all_results[source_name]['results']
                    new_results = source_result['results']
                    
                    # Simple deduplication based on URL/ID/content
                    combined_results = self._deduplicate_results(existing_results + new_results, source_name)
                    all_results[source_name]['results'] = combined_results
                    all_results[source_name]['count'] = len(combined_results)
        
        return {
            'search_term': f"({' OR '.join(terms)})",
            'sources_searched': list(combined_sources_searched),
            'results': all_results
        }
    
    def _execute_and_search(self, terms: List[str], sources: List[str], 
                           quiet: bool, **kwargs) -> Dict[str, Any]:
        """Execute AND search - find intersection of results"""
        if not quiet:
            print(f"📝 AND search across {len(terms)} terms: {', '.join(terms)}")
        
        all_term_results = []
        
        # Search each term separately
        for i, term in enumerate(terms):
            if not quiet:
                print(f"  🔍 Term {i+1}/{len(terms)}: '{term}'")
            
            term_results = self._execute_simple_search(term, sources, True, **kwargs)  # quiet=True
            
            if 'error' in term_results:
                continue
                
            all_term_results.append(term_results)
        
        if not all_term_results:
            return {
                'search_term': f"({' AND '.join(terms)})",
                'sources_searched': [],
                'results': {}
            }
        
        # Find intersection of results
        intersected_results = {}
        combined_sources_searched = set()
        
        # Start with results from first term
        first_results = all_term_results[0]
        combined_sources_searched.update(first_results.get('sources_searched', []))
        
        for source_name, source_result in first_results.get('results', {}).items():
            if source_result['status'] != 'success' or not source_result.get('results'):
                continue
            
            # Get results for this source from all other terms
            source_results_by_term = [source_result['results']]
            
            for term_results in all_term_results[1:]:
                combined_sources_searched.update(term_results.get('sources_searched', []))
                other_source_result = term_results.get('results', {}).get(source_name, {})
                if other_source_result.get('status') == 'success':
                    source_results_by_term.append(other_source_result.get('results', []))
                else:
                    # If any term doesn't have results for this source, no intersection
                    source_results_by_term = []
                    break
            
            if source_results_by_term and len(source_results_by_term) == len(terms):
                # Find intersection based on content similarity
                intersected_items = self._intersect_results(source_results_by_term, source_name, terms)
                
                if intersected_items:
                    intersected_results[source_name] = {
                        'status': 'success',
                        'source': source_name,
                        'results': intersected_items,
                        'count': len(intersected_items)
                    }
                    # Copy other metadata from first result
                    for key, value in source_result.items():
                        if key not in ['results', 'count']:
                            intersected_results[source_name][key] = value
        
        return {
            'search_term': f"({' AND '.join(terms)})",
            'sources_searched': list(combined_sources_searched),
            'results': intersected_results
        }
    
    def _deduplicate_results(self, results: List[Dict], source_name: str) -> List[Dict]:
        """Deduplicate results based on content"""
        seen = set()
        deduplicated = []
        
        for result in results:
            # Create a deduplication key based on the result type
            if source_name == 'malpedia':
                key = result.get('url', '') or result.get('title', '')
            elif source_name == 'otx':
                key = result.get('id', '')
            elif source_name == 'rss':
                key = result.get('url', '') or result.get('link', '')
            elif source_name == 'threatfox':
                key = result.get('ioc_value', '')
            elif source_name in ['shodan', 'ipgeo']:
                key = result.get('ip', '')
            elif source_name == 'crtsh':
                key = f"{result.get('common_name', '')}-{result.get('issuer_name', '')}"
            else:
                # Fallback: use string representation
                key = str(result)
            
            if key and key not in seen:
                seen.add(key)
                deduplicated.append(result)
        
        return deduplicated
    
    def _intersect_results(self, results_by_term: List[List[Dict]], source_name: str, terms: List[str]) -> List[Dict]:
        """Find intersection of results from multiple terms"""
        if not results_by_term or len(results_by_term) < 2:
            return results_by_term[0] if results_by_term else []
        
        # For AND search, we want items that contain ALL terms
        # We'll check if each result item contains all search terms
        intersected = []
        
        # Take the smallest result set as base to optimize
        base_results = min(results_by_term, key=len)
        
        for result in base_results:
            # Check if this result contains all search terms
            if self._result_contains_all_terms(result, terms, source_name):
                intersected.append(result)
        
        return intersected
    
    def _result_contains_all_terms(self, result: Dict, terms: List[str], source_name: str) -> bool:
        """Check if a result contains all search terms"""
        # Get searchable text from the result
        searchable_text = self._get_searchable_text(result, source_name).lower()
        
        # Check if all terms are present
        for term in terms:
            if term.lower() not in searchable_text:
                return False
        
        return True
    
    def _get_searchable_text(self, result: Dict, source_name: str) -> str:
        """Extract searchable text from a result based on source type"""
        text_parts = []
        
        if source_name == 'malpedia':
            text_parts.extend([
                result.get('title', ''),
                result.get('author', ''),
                result.get('url', '')
            ])
        elif source_name == 'otx':
            text_parts.extend([
                result.get('name', ''),
                result.get('description', ''),
                ' '.join(result.get('tags', []))
            ])
        elif source_name == 'rss':
            text_parts.extend([
                result.get('title', ''),
                result.get('description', ''),
                result.get('summary', ''),
                result.get('content', ''),
                result.get('source', ''),
                result.get('feed_name', '')
            ])
        elif source_name == 'threatfox':
            text_parts.extend([
                result.get('ioc_value', ''),
                result.get('malware_printable', ''),
                result.get('malware', ''),
                result.get('threat_type', ''),
                result.get('tags', '')
            ])
        elif source_name in ['shodan', 'ipgeo']:
            text_parts.extend([
                result.get('ip', ''),
                ' '.join(result.get('hostnames', [])),
                ' '.join(result.get('tags', [])),
                result.get('org', ''),
                result.get('country', '')
            ])
        elif source_name == 'crtsh':
            text_parts.extend([
                result.get('common_name', ''),
                result.get('name_value', ''),
                result.get('issuer_name', '')
            ])
        else:
            # Fallback: convert entire result to string
            text_parts.append(str(result))
        
        return ' '.join(filter(None, text_parts))

# Global instance
search_orchestrator = SearchOrchestrator()

def search_with_operators(search_term: str, sources: List[str] = None, 
                         quiet: bool = False, **kwargs) -> Dict[str, Any]:
    """Main entry point for searches with logical operator support"""
    return search_orchestrator.search_with_logical_operators(
        search_term, sources, quiet, **kwargs
    ) 