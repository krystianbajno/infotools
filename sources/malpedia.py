import os
import re
import requests

MALPEDIA_BIB_URL = "https://malpedia.caad.fkie.fraunhofer.de/library/download"

DATA_DIR = os.path.join(os.getcwd(), "data", "malpedia")
os.makedirs(DATA_DIR, exist_ok=True)
BIB_FILE = os.path.join(DATA_DIR, "malpedia.bib")

def download_bibliography() -> str:
    if os.path.exists(BIB_FILE):
        file_age = (os.path.getmtime(BIB_FILE))
        return BIB_FILE
    resp = requests.get(MALPEDIA_BIB_URL)
    if resp.status_code == 200:
        with open(BIB_FILE, "wb") as f:
            f.write(resp.content)
        return BIB_FILE
    raise Exception("Failed to download Malpedia bibliography")

def parse_bibliography_for_search(bib_file: str, search_term: str):
    """Parse bibliography file and search for entries matching the search term"""
    references = []
    search_lower = search_term.lower()
    
    with open(bib_file, "r", encoding="utf-8", errors="ignore") as f:
        bib_content = f.read()
    
    entries = bib_content.split("\n@")
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue

        # Extract all fields first
        entry_data = {}
        
        # Extract title
        title_match = re.search(r'title\s*=\s*{(.*?)}', entry, re.DOTALL)
        if title_match:
            entry_data["title"] = title_match.group(1).replace("\n", " ").strip()
        
        # Extract author
        author_match = re.search(r'author\s*=\s*{(.*?)}', entry, re.DOTALL)
        if author_match:
            entry_data["author"] = author_match.group(1).replace("\n", " ").strip()
        
        # Extract URL
        url_match = re.search(r'url\s*=\s*{(.*?)}', entry, re.DOTALL)
        if url_match:
            entry_data["url"] = url_match.group(1).strip()
        
        # Extract year
        year_match = re.search(r'year\s*=\s*{(.*?)}', entry)
        if year_match:
            entry_data["year"] = year_match.group(1).strip()
        
        # Extract date
        date_match = re.search(r'date\s*=\s*{(.*?)}', entry)
        if date_match:
            entry_data["date"] = date_match.group(1).strip()
        
        # Only search in title and author fields (exclude URL)
        if "title" in entry_data:
            searchable_text = f"{entry_data.get('title', '')} {entry_data.get('author', '')}".lower()
            if search_lower in searchable_text:
                references.append(entry_data)
        
    return references

def collect_malpedia_data(search_term: str):
    """
    Collect Malpedia bibliography data matching the search term
    
    Args:
        search_term: Simple search term (parsing handled at service level)
        
    Returns:
        List of bibliography references matching the search term
    """
    try:
        bib_file = download_bibliography()
        references = parse_bibliography_for_search(bib_file, search_term)
        return references
    except Exception as e:
        # Re-raise exception to be handled by service layer
        raise Exception(f"Malpedia search failed: {str(e)}")
