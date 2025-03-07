#!/usr/bin/env python3
import logging
from email import policy
from email.parser import BytesParser
import eml_parser # type: ignore

logger = logging.getLogger(__name__)

class EmailParser:
    """Parses email content into structured format."""

    def parse_email(self, email_content):
        """
        Parse email content into structured format.
        Args:
            email_content: Raw email content
        Returns:
            Tuple of (email object, parsed data or error message)
        """
        try:
            eml = BytesParser(policy=policy.default).parsebytes(email_content)
            parsed_data = None
            if eml_parser:
                parser = eml_parser.EmlParser()
                parsed_data = parser.decode_email_bytes(email_content)
            else:
                parsed_data = {
                    "header": dict(eml.items()),
                    "body": eml.get_payload()
                }
            return eml, parsed_data
        except Exception as e:
            logger.error(f"Email parsing failed: {str(e)}")
            return None, f"Parsing failed: {str(e)}"