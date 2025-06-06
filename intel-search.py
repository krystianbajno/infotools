#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

from services.search_service import (
    search_all_sources, 
    get_available_sources, 
    validate_source_requirements,
    AVAILABLE_SOURCES
)
from sources.print_service import (
    print_unified_results, 
    print_source_summary, 
    print_errors
)
from sources.report_generator import save_report

def main():
    parser = argparse.ArgumentParser(
        description="Search intelligence sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "ransomware"                    # Search all sources
  %(prog)s "APT28" --sources malpedia otx  # Search specific sources
  %(prog)s "CVE-2024" --sources rss        # Search only RSS feeds
  %(prog)s --list-sources                  # Show available sources
  %(prog)s --check-requirements            # Check API key configuration
        """
    )
    
    parser.add_argument(
        "search_term",
        nargs='?',
        help="Search term to look for across intelligence sources"
    )
    
    parser.add_argument(
        "--sources", "-s",
        nargs='+',
        choices=['malpedia', 'otx', 'rss', 'threatfox', 'shodan', 'ipgeo', 'crtsh'],
        help="Specific sources to search (default: all available)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show verbose output including full content and error details"
    )
    
    # General options
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Reload all cached data and feeds"
    )
    
    # Report generation options
    parser.add_argument(
        "--report",
        choices=['html', 'json', 'both'],
        help="Generate report in specified format (html, json, or both)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Directory to save reports (default: current directory)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output only JSON data (no progress messages, useful for piping to other tools)"
    )
    
    # Information options
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="List all available sources and exit"
    )
    
    parser.add_argument(
        "--check-requirements",
        action="store_true",
        help="Check if source requirements (API keys) are configured"
    )

    args = parser.parse_args()

    # Suppress logging when using JSON output
    if args.json:
        logging.getLogger().setLevel(logging.CRITICAL)
        logging.getLogger('httpx').setLevel(logging.CRITICAL)
        logging.getLogger('sources.crtsh_subdomains').setLevel(logging.CRITICAL)
        logging.getLogger('urllib3').setLevel(logging.CRITICAL)
        logging.getLogger('requests').setLevel(logging.CRITICAL)

    # Handle information requests
    if args.list_sources:
        sources = get_available_sources()
        print("Available Intelligence Sources:")
        print("=" * 50)
        for source_id, source_info in sources.items():
            api_status = " (requires API key)" if source_info['requires_api'] else ""
            print(f"{source_id.upper()}: {source_info['name']}{api_status}")
            print(f"  Description: {source_info['description']}")
            print()
        return

    if args.check_requirements:
        issues = validate_source_requirements()
        if not issues:
            print("✅ All source requirements are met!")
        else:
            print("⚠️  Source requirement issues:")
            for source, issue in issues.items():
                print(f"  {source.upper()}: {issue}")
            print("\nTo fix OTX issue:")
            print("  1. Sign up at https://otx.alienvault.com/")
            print("  2. Get your API key from profile settings")
            print("  3. Add to infotools/.env: OTX_API_KEY=your_key_here")
        return

    # Require search term for actual searches
    if not args.search_term:
        parser.error("search_term is required unless using --list-sources or --check-requirements")

    # Prepare search parameters
    search_params = {
        'reload': args.reload
    }

    # Determine sources to search
    sources_to_search = args.sources
    if not sources_to_search:
        # Check requirements and warn about missing API keys
        issues = validate_source_requirements()
        available_sources = get_available_sources()
        sources_to_search = list(available_sources.keys())
        
        if issues and not args.json:
            print("⚠️  Some sources may not work due to missing requirements:")
            for source, issue in issues.items():
                print(f"  {source.upper()}: {issue}")
            print()

    # Display search info (unless JSON-only output)
    if not args.json:
        print("=" * 70)
        print(f"🎯 THREAT INTELLIGENCE SEARCH")
        print("=" * 70)
        print(f"📝 Query: {args.search_term}")
        print(f"📚 Sources: {', '.join(AVAILABLE_SOURCES[s]['name'] for s in sources_to_search)}")
        if args.reload:
            print("🔄 Cache: Reloading all data")
        print("-" * 70)

    try:
        # Perform the search
        results = search_all_sources(
            search_term=args.search_term,
            sources=sources_to_search,
            quiet=args.json,
            **search_params
        )

        if 'error' in results:
            if args.json:
                # Output error as JSON
                error_data = {
                    'error': results['error'],
                    'available_sources': results.get('available_sources', [])
                }
                print(json.dumps(error_data, indent=2))
            else:
                print(f"❌ Search error: {results['error']}", file=sys.stderr)
                if 'available_sources' in results:
                    print(f"Available sources: {results['available_sources']}", file=sys.stderr)
            sys.exit(1)

        # Prepare results for unified printing
        unified_results = {}
        
        # Convert service results to print service format
        for source_name, source_result in results['results'].items():
            if source_result['status'] == 'success' and source_result['results']:
                if source_name == 'malpedia':
                    unified_results['malpedia'] = source_result['results']
                elif source_name == 'otx':
                    unified_results['otx'] = {'pulses': source_result['results']}
                elif source_name == 'rss':
                    unified_results['rss'] = {
                        'articles': source_result['results'],
                        'errors': source_result.get('errors', [])
                    }
                # elif source_name == 'stix':
                #     unified_results['stix'] = {
                #         'objects': source_result['results'],
                #         'errors': source_result.get('errors', [])
                #     }
                elif source_name == 'threatfox':
                    unified_results['threatfox'] = {
                        'iocs': source_result['results'],
                        'total_iocs_in_db': source_result.get('total_iocs_in_db', 0),
                        'cache_age': source_result.get('cache_age', 'Unknown'),
                        'error': source_result.get('error', None)
                    }
                elif source_name == 'shodan':
                    unified_results['shodan_internetdb'] = {
                        'results': source_result['results'],
                        'ips_found': source_result.get('ips_found', 0),
                        'errors': source_result.get('errors', [])
                    }
                elif source_name == 'ipgeo':
                    unified_results['ip_geolocation'] = {
                        'results': source_result['results'],
                        'ips_found': source_result.get('ips_found', 0),
                        'errors': source_result.get('errors', [])
                    }
                elif source_name == 'crtsh':
                    unified_results['crtsh_subdomains'] = {
                        'subdomains': source_result['results'],
                        'total_found': source_result.get('count', 0),
                        'domain_searched': source_result.get('domain_searched'),
                        'errors': source_result.get('errors', [])
                    }

        if args.json:
            # JSON-only output: print clean JSON and exit
            output_data = {
                'search_term': args.search_term,
                'sources_searched': sources_to_search,
                'results': unified_results,
                'metadata': {
                    'total_results': sum(len(source_data.get('subdomains', source_data.get('results', source_data.get('articles', source_data.get('iocs', source_data.get('pulses', [])))))) for source_data in unified_results.values()),
                    'sources_with_results': list(unified_results.keys())
                }
            }
            print(json.dumps(output_data, indent=2, default=str))
        else:
            # Standard output with formatting
            if unified_results:
                print("\n" + "=" * 70)
                print("📊 SEARCH RESULTS")
                print("=" * 70)
                print_unified_results(unified_results, args.verbose)
                
                print("\n" + "-" * 70)
                print_source_summary(unified_results)
                print_errors(unified_results, args.verbose)
            else:
                print("\n" + "=" * 70)
                print("❌ NO RESULTS FOUND")
                print("=" * 70)
                print("No results were found across all searched sources.")
                print("Try adjusting your search term or expanding source selection.")

            # Print any source-level errors
            source_errors = []
            for source_name, source_result in results['results'].items():
                if source_result['status'] == 'error':
                    source_errors.append(f"{AVAILABLE_SOURCES[source_name]['name']}: {source_result['error']}")
            
            if source_errors:
                print(f"\n🚨 SOURCE ERRORS:")
                for error in source_errors:
                    print(f"  • {error}")

            # Generate report if requested
            if args.report:
                print(f"\n📋 REPORT GENERATION")
                print("-" * 30)
                print(f"Generating {args.report.upper()} report...")
                try:
                    saved_files = save_report(
                        results=unified_results,
                        search_term=args.search_term,
                        report_format=args.report,
                        output_dir=args.output_dir
                    )
                    print(f"✅ Report saved: {saved_files}")
                except Exception as e:
                    print(f"❌ Error generating report: {e}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\n🛑 Search interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 