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

def parse_bibliography_for_search(bib_file: str, search):
    references = []
    # Parse search term for logical operators
    search_query = parse_search_term(search)
    
    with open(bib_file, "r", encoding="utf-8", errors="ignore") as f:
        bib_content = f.read()
    entries = bib_content.split("\n@")
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue

        if search_query.matches_text(entry):
            entry_data = {}
            title_match = re.search(r'title\s*=\s*{(.*?)}', entry, re.DOTALL)
            if title_match:
                entry_data["title"] = title_match.group(1).replace("\n", " ").strip()
            author_match = re.search(r'author\s*=\s*{(.*?)}', entry, re.DOTALL)
            if author_match:
                entry_data["author"] = author_match.group(1).replace("\n", " ").strip()
            url_match = re.search(r'url\s*=\s*{(.*?)}', entry, re.DOTALL)
            if url_match:
                entry_data["url"] = url_match.group(1).strip()
            year_match = re.search(r'year\s*=\s*{(.*?)}', entry)
            if year_match:
                entry_data["year"] = year_match.group(1).strip()
            date_match = re.search(r'date\s*=\s*{(.*?)}', entry)
            if date_match:
                entry_data["date"] = date_match.group(1).strip()
            if "title" in entry_data:
                references.append(entry_data)
        
    return references

def collect_malpedia_data(search: str):
    try:
        bib_file = download_bibliography()
        references = parse_bibliography_for_search(bib_file, search)
        return references
    except Exception as e:
        references = []
