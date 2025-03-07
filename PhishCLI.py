#!/usr/bin/env python3
import os
import sys
import time
import logging
import argparse
import mailbox
import toml # type: ignore
from pathlib import Path
from report import EmailParser
from security_checks import SecurityChecks
from Email_Analysis import EmailAnalysis

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler("email_analysis.log")]
)
logger = logging.getLogger(__name__)

# Uncomment teh following sectionif you want to add a env path containing you API-KEY
# Load the .vt.toml file from a specific location

# --------------------------------------------------------------------------------
# vt_config_path = "<path>"  # Replace with the actual absolute path to .vt.toml
# logger.info(f"Attempting to load .vt.toml file from: {vt_config_path}")


# def load_vt_config(config_path):
#     """Load VirusTotal API key from .vt.toml file."""
#     try:
#         path = Path(config_path).expanduser()
#         if not path.exists():
#             logger.error(f".vt.toml file not found at: {path}")
#             sys.exit(1)
#         config = toml.load(path)
#         api_key = config.get("apikey")
#         if not api_key:
#             logger.error("No 'apikey' found in .vt.toml file")
#             sys.exit(1)
#         logger.info(f"API key loaded successfully from {config_path}")
#         return api_key
#     except Exception as e:
#         logger.error(f"Failed to load .vt.toml: {str(e)}")
#         sys.exit(1)

# # Load API key
# api_key = load_vt_config(vt_config_path)
# --------------------------------------------------------------------------------


class EmailAnalyzer:
    def __init__(self, api_key, output_file="phishing_report.txt", verbose=False, format_output="text"):
        self.output_file = output_file
        self.verbose = verbose
        self.format_output = format_output
        self.api_key = api_key
        if not self.api_key:
            logger.error("No VirusTotal API key provided")
            sys.exit(1)
        logger.info("API key successfully initialized")
        self.parser = EmailParser()
        self.security = SecurityChecks()
        self.analysis = EmailAnalysis(self.api_key)
        self.suspicious_keywords = {"urgent", "login", "verify", "password", "account", "update", "security"}

    def calculate_risk_score(self, auth_results, url_results, body, attachment_results):
        score = 0
        auth_fails = []
        high_mal_urls = []

        # Authentication checks
        for result in auth_results:
            if "DKIM: Fail" in result:
                score += 10
                auth_fails.append("DKIM failure")
                logger.debug(f"DKIM Fail: +10, Score: {score}")
            elif "DKIM" in result and "Pass" not in result and "Fail" not in result:
                logger.debug(f"DKIM Not checked or neutral: +0, Score: {score}")
            if "SPF: Fail" in result:
                score += 5
                auth_fails.append("SPF failure")
                logger.debug(f"SPF Fail: +5, Score: {score}")
            elif "SPF" in result and "Pass" not in result and "Fail" not in result:
                logger.debug(f"SPF Not checked or neutral: +0, Score: {score}")
            if "DMARC: Fail" in result:
                score += 25
                auth_fails.append("DMARC failure")
                logger.debug(f"DMARC Fail: +25, Score: {score}")
            elif "DMARC: No policy" in result:
                score += 10
                auth_fails.append("DMARC no policy")
                logger.debug(f"DMARC No Policy: +10, Score: {score}")
            elif "DMARC" in result and "Pass" not in result and "Fail" not in result and "No policy" not in result:
                logger.debug(f"DMARC Not checked or neutral: +0, Score: {score}")

        # URL analysis
        unique_urls = {result.split(" - ")[0]: result for result in url_results}.values()
        for result in unique_urls:
            if "Malicious" in result:
                try:
                    mal_count = int(result.split("Malicious: ")[1].split(",")[0])
                    susp_count = int(result.split("Suspicious: ")[1].split(")")[0])
                    if mal_count >= 5:
                        score += 50
                        high_mal_urls.append(result.split(" - ")[0])
                        logger.debug(f"High Malicious URL: {result}, +50, Score: {score}")
                    elif mal_count >= 3:
                        score += 30
                        logger.debug(f"Moderate Malicious URL: {result}, +30, Score: {score}")
                    elif mal_count >= 1:
                        score += 10
                        logger.debug(f"Low Malicious URL: {result}, +10, Score: {score}")
                    elif susp_count >= 3:
                        score += 15
                        logger.debug(f"High Suspicious URL: {result}, +15, Score: {score}")
                    elif susp_count >= 1:
                        score += 5
                        logger.debug(f"Low Suspicious URL: {result}, +5, Score: {score}")
                except (IndexError, ValueError):
                    score += 10
                    logger.debug(f"Unclear URL: {result}, +10, Score: {score}")

        # Content analysis
        body_lower = body.lower()
        keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in body_lower)
        content_score = min(keyword_count * 5, 20)
        score += content_score
        logger.debug(f"Content score from {keyword_count} keywords: {content_score}, Total: {score}")

        # Attachments
        mal_attachments = []
        for result in attachment_results:
            if "❌ Malicious" in result:
                score += 50
                mal_attachments.append(result)
                logger.debug(f"Malicious attachment: {result}, +50, Score: {score}")
            elif "⚠️ Suspicious" in result:
                score += 30
                logger.debug(f"Suspicious attachment: {result}, +30, Score: {score}")
            elif "risky file type" in result:
                score += 15
                logger.debug(f"Risky attachment: {result}, +15, Score: {score}")

        score = max(0, score)
        risk_level = "HIGH" if score >= 80 else "MEDIUM" if score >= 30 else "LOW" if score >= 10 else "MINIMAL"
        reasons = []
        if high_mal_urls:
            reasons.append(f"highly malicious URL(s): {', '.join(high_mal_urls)}")
        if len(auth_fails) >= 2:
            reasons.append(f"multiple authentication failures: {', '.join(auth_fails)}")
        elif auth_fails:
            reasons.append(f"authentication issue: {auth_fails[0]}")
        if mal_attachments:
            reasons.append("malicious attachment(s) detected")
        reason_text = " and ".join(reasons) if reasons else "unspecified factors"
        logger.info(f"Final risk score: {score}, Level: {risk_level}, Reason: {reason_text}")
        return score, risk_level, reason_text

    def generate_report(self, email_content, email_index=None):
        try:
            email, parsed = self.parser.parse_email(email_content)
            if not email:
                report = [f"Email {email_index or ''} Analysis", "="*50, "❌ " + parsed, "="*50]
                self._write_report(report)
                return f"❌ Failed to analyze email {email_index or ''}"
            headers = dict(email.items())
            body = "".join(part.get_payload() for part in email.walk() if part.get_content_type() == "text/plain") if email.is_multipart() else email.get_payload()
            auth_results = [self.security.check_dkim(email_content), self.security.check_spf(headers), self.security.check_dmarc(headers)]
            url_results = self.analysis.analyze_urls(body)
            attachment_results = self.analysis.analyze_attachments(email)
            risk_score, risk_level, reason_text = self.calculate_risk_score(auth_results, url_results, body, attachment_results)
            subject = headers.get('Subject', 'Unknown')
            subject = subject[:97] + "..." if len(subject) > 100 else subject
            
            report = [
                f"Email {email_index or ''} Analysis", "="*50,
                f"⚠️ RISK LEVEL: {risk_level} (Score: {risk_score}/100)",
                f"📅 Date: {headers.get('Date', 'Unknown')}", f"👤 From: {headers.get('From', 'Unknown')}",
                f"📧 To: {headers.get('To', 'Unknown')}", f"📌 Subject: {subject}",
                f"🔑 Message-ID: {headers.get('Message-ID', 'Unknown')}", "\n🔒 Authentication Checks:"
            ]
            for result in auth_results:
                report.append(f"  {'✅' if 'Pass' in result else '❌' if 'Fail' in result else '⚠️'} {result}")

            report.append("\n🔗 URL Analysis (Threshold: Malicious >= 5 High, >= 3 Moderate, >= 1 Low):")
            unique_urls = {result.split(" - ")[0]: result for result in url_results}.values()
            safe_count, susp_count, mal_count = 0, 0, 0
            for result in unique_urls:
                if "No URLs found" in result:
                    report.append(f"  ℹ️ {result}")
                    safe_count += 1
                elif "Safe" in result and "Malicious: 0" in result and "Suspicious: 0" in result:
                    report.append(f"  ✅ {result}")
                    safe_count += 1
                elif "Malicious" in result or "Suspicious" in result:
                    try:
                        mal_count_val = int(result.split("Malicious: ")[1].split(",")[0])
                        susp_count_val = int(result.split("Suspicious: ")[1].split(")")[0])
                        if mal_count_val >= 5:
                            report.append(f"  ❌ {result}")
                            mal_count += 1
                        elif mal_count_val >= 3:
                            report.append(f"  ⚠️ {result} (Moderate risk)")
                            susp_count += 1
                        elif mal_count_val >= 1 or susp_count_val >= 1:
                            report.append(f"  ⚠️ {result}")
                            susp_count += 1
                        else:
                            report.append(f"  ✅ {result}")
                            safe_count += 1
                    except (IndexError, ValueError):
                        report.append(f"  ⚠️ {result} (Analysis unclear)")
                        susp_count += 1
                else:
                    report.append(f"  ⚠️ {result} (Analysis unclear)")
                    susp_count += 1
            
            report.append(f"\nURL Summary: {safe_count} Safe, {susp_count} Suspicious, {mal_count} Malicious")

            report.extend(["\n📎 Attachment Analysis:"] + [f"  {'ℹ️' if 'No attachments' in r else ''}{r}" for r in attachment_results])
            report.append("\n💡 Recommendations:")
            if risk_level == "HIGH":
                report.extend([
                    f"  ❌ This email is considered high risk due to {reason_text}.",
                    "  ❌ Do not interact with any links or attachments.",
                    "  ❌ Report to your security team immediately."
                ])
            elif risk_level == "MEDIUM":
                report.extend(["  ⚠️ This email shows some suspicious characteristics.", "  ⚠️ Proceed with caution and verify sender through other channels."])
            elif risk_level == "LOW":
                report.extend(["  ⚠️ This email has minor issues but may be legitimate.", "  ⚠️ Verify sender if anything seems unusual."])
            else:
                report.append("  ✅ This email appears to be legitimate.")
            report.append("="*50)
            self._write_report(report)
            return f"✅ Report for email {email_index or ''} generated successfully"
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return f"❌ Failed to generate report: {str(e)}"

    def _write_report(self, report_lines):
        try:
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write("\n".join(map(str, report_lines)) + "\n\n")
        except Exception as e:
            logger.error(f"Error writing report: {str(e)}")

    def process_file(self, file_path):
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return
        if os.path.exists(self.output_file):
            try:
                os.remove(self.output_file)
            except Exception as e:
                logger.error(f"Failed to clear previous report: {str(e)}")
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(f"# Email Security Analysis Report\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        if file_path.lower().endswith('.eml'):
            logger.info(f"Processing EML file: {file_path}")
            with open(file_path, 'rb') as f:
                email_content = f.read()
            result = self.generate_report(email_content)
            logger.info(result)
        elif file_path.lower().endswith('.mbox'):
            logger.info(f"Processing MBOX file: {file_path}")
            try:
                mbox = mailbox.mbox(file_path)
                total = len(mbox)
                logger.info(f"Found {total} emails in mbox file")
                for i, message in enumerate(mbox, 1):
                    logger.info(f"Processing email {i}/{total}")
                    email_content = message.as_bytes()
                    result = self.generate_report(email_content, email_index=i)
                    logger.info(result)
                    sys.stdout.write(f"\rProcessed {i}/{total} emails ({(i/total)*100:.1f}%)")
                    sys.stdout.flush()
                sys.stdout.write("\rProcessing complete!                \n")
            except Exception as e:
                logger.error(f"Error processing mbox file: {str(e)}")
        else:
            logger.error("Unsupported file type. Use .eml or .mbox")
        logger.info(f"Analysis complete. Report saved to {os.path.abspath(self.output_file)}")

def main():
    parser = argparse.ArgumentParser(description="Email Phishing Analysis Tool")
    parser.add_argument("file", help="Email file (.eml or .mbox) to analyze")
    parser.add_argument("-o", "--output", default="phishing_report.txt", help="Output file for the report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--format", choices=["text", "html", "json"], default="text", help="Output format")
    parser.add_argument("-k", "--apikey", help="VirusTotal API key (overrides .vt.toml)")
    args = parser.parse_args()

    effective_api_key = args.apikey or api_key # type: ignore
    analyzer = EmailAnalyzer(
        api_key=effective_api_key,
        output_file=args.output,
        verbose=args.verbose,
        format_output=args.format
    )
    analyzer.process_file(args.file)

if __name__ == "__main__":
    main()