"""
el_ingest.py

This ingests the eml files for review

Processes eml files in the ./emails folder
"""

from pathlib import Path
from email import policy
from email.parser import BytesParser
import re
import ipaddress
import os

"""
list_eml_files

Returns a list of all eml files in the emails folder
"""
def list_eml_files():
    email_folder = Path("emails")
    if not email_folder.exists() or not email_folder.is_dir():
            print("emails folder not found.")
            return
    # Return eml files only
    return sorted(email_folder.glob("*.eml"))

"""
parse_header

Returns a header structure containing some fields from the eml header
"""
def parse_header(eml_path):
    with open(eml_path, "rb") as binary_email:
        structured_email = BytesParser(policy = policy.default).parse(binary_email)

    # Gather info from header into a structure
    header = {
         "From": structured_email.get("From", "N/A"),
         "To": structured_email.get("To", "N/A"),
         "Reply-To": structured_email.get("Reply-To", "N/A"),
         "Subject": structured_email.get("Subject", "N/A"),
         "Date": structured_email.get("Date", "N/A"),
         "Received": structured_email.get_all("Received", [])
    }
    return header

"""
extract_body

Returns the extracted body of the supplied eml file
"""
def extract_body(eml_path):
    with open(eml_path, "rb") as binary_email:
        msg = BytesParser(policy = policy.default).parse(binary_email)

    # Multipart email logic
    if msg.is_multipart():
        plain_parts = []
        html_parts = []
        for part in msg.walk():
            # Skip attachments
            if part.get_content_disposition() == "attachment":
                continue

            # Extract text/plain
            if part.get_content_type() == "text/plain":
                plain_parts.append(part.get_content())
            # Html fallback only if no plain text exists
            elif part.get_content_type() == "text/html":
                html_parts.append(part.get_content())

        # Join all the text pieces together and return
        # Prefer to return plain text, if not exist then return html
        if plain_parts:
            return "\n".join(plain_parts).strip()
        if html_parts:
            return "\n".join(html_parts).strip()
        return "--- Failed to extract body contents ---"

    # Single part email logic
    else:
        return msg.get_content().strip()

"""
extract_hop_ips

Returns a list of all ips from the Received section of the header
"""
def extract_hop_ips(received_list):
    ips = []
    for hop in received_list:
          # re matches IPv4
          ip_match = re.findall(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', hop)
          ips.extend(ip_match)
    return ips


"""
get_ip_classification

Returns IP type of given IP (Loopback, private, public, invalid)
"""
def get_ip_classification(ip):
     try:
          ipaddress_object = ipaddress.ip_address(ip)
          if ipaddress_object.is_loopback:
               return "Loopback"
          elif ipaddress_object.is_private:
               return "Private"
          else:
               return "Public"
     except ValueError:
          return "Invalid"
     
"""
extract_urls

Returns a list of all urls in provided text
"""
def extract_urls(text):
    if not text:
         return []
    
    # Finds http://, https://, and www.
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

"""
extract_attachments

Returns the attachments of the supplied eml file
"""
def extract_attachments(eml_path):
     attachments = []
     with open(eml_path, "rb") as binary_email:
        msg = BytesParser(policy = policy.default).parse(binary_email)

     for part in msg.walk():
          # get attachments
          if part.get_content_disposition() == "attachment":
               filename = part.get_filename()

               # Skip if no filename
               if not filename:
                    continue

               # Grab extension, mime, payload and size
               extension = os.path.splitext(filename)[1].lower()
               mime = part.get_content_type()
               payload = part.get_payload(decode=True)
               size = len(payload) if payload else 0

               # Create a structure representing the attachment's data
               attachments.append({
                    "filename": filename,
                    "extension": extension,
                    "mime": mime,
                    "size": size
               })
               
     return attachments