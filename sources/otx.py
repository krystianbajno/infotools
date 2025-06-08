import requests

def collect_otx_data(search_term: str, api_key: str = None, quiet: bool = False) -> dict:
    """
    Collect intelligence data from AlienVault OTX for a specific search term.
    """
    
    if not api_key:
        return {"status": "error", "error": "OTX API key not configured"}

    # Query OTX API for the search term
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": "APTSEARCH/2.0"}
    pulses = []
    seen = set()
    url = f"https://otx.alienvault.com/api/v1/search/pulses?q={search_term}&sort=-modified"
    try:
        if not quiet:
            print("Collecting OTX data for search: ", search_term)

        resp = requests.get(url, headers=headers, timeout=30)

        if resp.status_code == 200:
            data = resp.json()
            for pulse in data.get("results", []):
                pulse_id = pulse.get("id")
                if not pulse_id or pulse_id in seen:
                    continue
                seen.add(pulse_id)
                pulses.append({
                    "id": pulse_id,
                    "name": pulse.get("name"),
                    "description": pulse.get("description"),
                    "created": pulse.get("created"),
                    "author_name": pulse.get("author_name"),
                    "tags": pulse.get("tags", []),
                    "indicators": pulse.get("indicators", [])
                })
    except Exception as e:
        pass
    
    if not quiet:
        print("OTX: Pulses found for search: ", search_term, " - ", len(pulses))

    return {
        "search_term": search_term,
        "status": "success",
        "source": "AlienVault OTX",
        "pulse_count": len(pulses),
        "pulses": pulses
    } 