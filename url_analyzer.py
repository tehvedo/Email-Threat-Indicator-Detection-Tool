"""
url_analyzer.py

This analyzes URLs for anything out of the ordinary
"""

import ipaddress
from urllib.parse import urlparse

# Some TLDs considered to be suspicious. This could be tailored to liking.
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "support", "online", "info",
    "icu", "cyou", "monster", "live", "shop", "work"
}

"""
normalize_url

defaults URL scheme to http:// if no scheme present in URL
"""
def normalize_url(url):
    if "://" not in url:
        return "http://" + url
    return url

"""
is_raw_ip

Returns true if the host is a raw IP address
"""
def is_raw_ip(url):
    url = normalize_url(url)
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        # No hostname found
        if not hostname:
            return False

        # If this try succeeds, hostname is raw IP
        try:
            ip_obj = ipaddress.ip_address(hostname)
            return True
        except ValueError:
            # Not a raw IP
            return False

    # Parsing failed
    except Exception:
        return False

"""
has_suspicious_tld

Returns true if the TLD is in the suspicious list
"""
def has_suspicious_tld(url):
    url = normalize_url(url)
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        # No hostname found
        if not hostname:
            return False

        # Check for . before splitting on it
        if "." not in hostname:
            return False
        
        # Check TLD against suspicious list
        tld = hostname.split(".")[-1].lower()
        return tld in SUSPICIOUS_TLDS

    # Parsing failed
    except Exception:
        return False
    
"""
is_very_long

Returns true if the URL is excessively long (currently defined as 150+ characters)
"""
def is_very_long(url, limit=150):
    return len(url) > limit