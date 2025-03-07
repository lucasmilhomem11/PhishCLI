#!/usr/bin/env python3
import logging
import re
import dkim # type: ignore
import spf # type: ignore
import dmarc # type: ignore

logger = logging.getLogger(__name__)

class SecurityChecks:
    """Performs email authentication checks."""

    def check_dkim(self, email_content):
        """Verify DKIM signature."""
        if not dkim:
            return "DKIM: Module not installed"
        try:
            result = dkim.verify(email_content)
            return "DKIM: Pass" if result else "DKIM: Fail"
        except Exception as e:
            logger.warning(f"DKIM check failed: {str(e)}")
            return f"DKIM: Error ({str(e)})"

    def check_spf(self, headers):
        """Check SPF record."""
        received_spf = headers.get('Received-SPF', '')
        if received_spf:
            if 'pass' in received_spf.lower():
                return "SPF: Pass"
            elif 'fail' in received_spf.lower():
                return "SPF: Fail"
            elif 'softfail' in received_spf.lower():
                return "SPF: SoftFail"
            elif 'neutral' in received_spf.lower():
                return "SPF: Neutral"
            elif 'none' in received_spf.lower():
                return "SPF: None"
        if not spf:
            return "SPF: Module not installed"
        try:
            sender = re.findall(r'[\w\.-]+@[\w\.-]+', headers.get('From', 'unknown@example.com'))[0]
            received = headers.get('Received', '')
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received)
            ip = ip_match.group(0) if ip_match else None
            if not ip:
                return "SPF: Unknown (No source IP found)"
            result, explanation = spf.check2(i=ip, s=sender, h=headers.get('HELO', ''))
            return f"SPF: {result.capitalize()} ({explanation})"
        except Exception as e:
            logger.warning(f"SPF check error: {str(e)}")
            return f"SPF: Error ({str(e)})"

    def check_dmarc(self, headers):
        """Check DMARC policy."""
        auth_results = headers.get('Authentication-Results', '')
        if 'dmarc=pass' in auth_results.lower():
            return "DMARC: Pass"
        elif 'dmarc=fail' in auth_results.lower():
            return "DMARC: Fail"
        if not dmarc:
            return "DMARC: Module not installed"
        try:
            domain = re.search(r'@([\w.-]+)', headers.get('From', 'unknown@example.com'))
            if not domain:
                return "DMARC: Unknown (No domain found)"
            domain = domain.group(1)
            result = dmarc.get_dmarc_record(domain)
            if not result:
                return "DMARC: No policy found"
            policy = "unknown"
            if "p=none" in result.lower():
                policy = "None (Monitor)"
            elif "p=quarantine" in result.lower():
                policy = "Quarantine"
            elif "p=reject" in result.lower():
                policy = "Reject"
            return f"DMARC: Policy found - {policy}"
        except Exception as e:
            logger.warning(f"DMARC check error: {str(e)}")
            return f"DMARC: Error ({str(e)})"