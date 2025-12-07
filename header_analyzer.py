"""
header_analyzer.py

This analyzes headers for anything out of the ordinary
"""

"""
has_from_replyTo_mismatch

returns True if from and reply-to are mismatched
"""
def has_from_replyTo_mismatch(header):
    # If no Reply-To provided, cannot make a determination
    if header["Reply-To"] == "N/A":
        return False
    
    # Treat any malformed email address as bad
    if "@" not in header["From"] or "@" not in header["Reply-To"]:
        return True
    
    from_domain = header["From"].split("@")[-1].lower()
    reply_domain = header["Reply-To"].split("@")[-1].lower()

    # Return True if domains mismatch
    if from_domain != reply_domain:
        return True
    else:
        return False