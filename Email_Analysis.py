#!/usr/bin/env python3
import logging
import re
import hashlib
import time
import quopri
from functools import lru_cache
import os
import vt  # type: ignore 

logger = logging.getLogger(__name__)

class EmailAnalysis:
    """Analyzes URLs and attachments in emails using VirusTotal."""

    def __init__(self, api_key):
        self.client = vt.Client(api_key)  # Initialize vt-py client with API key
        # Note: If you want to keep using the session from config.py, you'll need to pass it and adapt headers

    @lru_cache(maxsize=100)
    def _vt_url_lookup(self, url):
        """Look up URL on VirusTotal using vt-py."""
        try:
            url_id = vt.url_id(url)  # Generate URL ID as required by VirusTotal API
            url_obj = self.client.get_object(f"/urls/{url_id}")
            stats = url_obj.last_analysis_stats
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0)
                        }
                    }
                }
            }
        except vt.APIError as e:
            if e.code == "NotFoundError":
                logger.info(f"URL not found in VT database: {url}, submitting for analysis")
                analysis = self.client.scan_url(url)
                # Optionally wait for analysis to complete
                time.sleep(60)  # Simple delay; consider polling or async for production
                return self._vt_url_lookup(url)  # Retry after submission
            logger.error(f"Error analyzing URL: {str(e)}")
            return None

    @lru_cache(maxsize=20)
    def _vt_file_lookup(self, file_hash):
        """Look up file hash on VirusTotal using vt-py."""
        try:
            file_obj = self.client.get_object(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0)
                        }
                    }
                }
            }
        except vt.APIError as e:
            logger.error(f"Error analyzing file: {str(e)}")
            return None

    def analyze_urls(self, body):
        """Find and analyze URLs in email body."""
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')
        try:
            body = quopri.decodestring(body.encode()).decode('utf-8', errors='ignore')
        except Exception:
            logger.warning("Failed to decode quoted-printable content")
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = re.findall(url_pattern, body)
        if not urls:
            return ["No URLs found"]
        results = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
            analysis = self._vt_url_lookup(url)
            if analysis:
                try:
                    stats = analysis['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    verdict = "Malicious" if malicious > 0 else "Suspicious" if suspicious > 0 else "Safe"
                    results.append(f"URL: {url} - {verdict} (Malicious: {malicious}, Suspicious: {suspicious})")
                except KeyError:
                    results.append(f"URL: {url} - Analysis incomplete (missing data)")
            else:
                results.append(f"URL: {url} - Analysis failed (API error)")
        return results

    def analyze_attachments(self, email):
        """Analyze email attachments."""
        if not email:
            return ["No email object available"]
        results = []
        for part in email.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get_content_disposition() in ['attachment', 'inline']:
                filename = part.get_filename()
                if not filename:
                    continue
                content = part.get_payload(decode=True)
                if not content:
                    results.append(f"Attachment: {filename} - Empty content")
                    continue
                file_size = len(content)
                file_hash = hashlib.sha256(content).hexdigest()
                results.append(f"Attachment: {filename} - Size: {file_size} bytes - SHA256: {file_hash}")
                ext = os.path.splitext(filename.lower())[1]
                risky_exts = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', 
                             '.hta', '.doc', '.docm', '.xls', '.xlsm', '.pdf']
                if ext in risky_exts:
                    results.append(f"  ⚠️ Potentially risky file type: {ext}")
                analysis = self._vt_file_lookup(file_hash)
                if analysis:
                    try:
                        stats = analysis['data']['attributes']['last_analysis_stats']
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        verdict = "❌ Malicious" if malicious > 0 else "⚠️ Suspicious" if suspicious > 0 else "✅ Safe"
                        results.append(f"  VirusTotal: {verdict} (Malicious: {malicious}, Suspicious: {suspicious})")
                    except KeyError:
                        results.append(f"  VirusTotal: Analysis incomplete (missing data)")
                else:
                    results.append(f"  VirusTotal: Analysis failed or file unknown")
        return results if results else ["No attachments found"]

    def __del__(self):
        """Ensure the client is closed when the object is destroyed."""
        self.client.close()