"""
VirusTotal API Integration for Memory Forensics
"""

import urllib.request
import urllib.error
import urllib.parse
import json
from dataclasses import dataclass
from loguru import logger

@dataclass
class VTResult:
    process: str
    vt_id: str = ""
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    error: str = ""
    vt_link: str = ""

class VirusTotalScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key.strip()
        self.base_url = "https://www.virustotal.com/api/v3/search?query="

    def scan_processes(self, process_names: list[str]) -> list[VTResult]:
        """
        Queries the VirusTotal v3 API for the given list of process names.
        Returns a list of VTResult objects containing threat scores.
        """
        if not self.api_key:
            return [VTResult(process="ERROR", error="API Key is missing.")]

        unique_names = set(p for p in process_names if p.strip())
        results = []

        logger.info(f"Querying VirusTotal for {len(unique_names)} unique process names.")

        for name in sorted(unique_names):
            try:
                url = self.base_url + urllib.parse.quote(name)
                req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                
                hits = data.get("data", [])
                if hits:
                    item = hits[0]
                    stats = item.get("attributes", {}).get("last_analysis_stats", {})
                    results.append(VTResult(
                        process=name,
                        vt_id=item.get("id", ""),
                        malicious=stats.get("malicious", 0),
                        suspicious=stats.get("suspicious", 0),
                        undetected=stats.get("undetected", 0),
                        vt_link=f"https://www.virustotal.com/gui/file/{item.get('id', '')}"
                    ))
                else:
                    results.append(VTResult(process=name, error="No matches found on VT."))

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    results.append(VTResult(process=name, error="Rate limit hit."))
                    break
                results.append(VTResult(process=name, error=f"HTTP Error: {e}"))
            except Exception as e:
                results.append(VTResult(process=name, error=f"Error: {e}"))

        return results
