"""
text_analyzer.py

This analyzes text (email body)
"""

# Phrases that relate to urgency
URGENT_LANGUAGE = {
    "immediately",
    "urgent",
    "asap",
    "right away",
    "act now",
    "final notice",
    "last warning",
    "attention required",
    "your account will close",
    "your account will be closed",
    "suspicious activity",
    "unusual activity",
    "verify now",
    "update now",
    "expires soon",
    "limited time",
    "time sensitive",
    "emergency"
}

# Phrases that relate to credentials
CREDENTIAL_LANGUAGE = {
    "verify your account",
    "verify account",
    "confirm your identity",
    "confirm your account",
    "reset your password",
    "enter your password",
    "login to continue",
    "log in to continue",
    "update your credentials",
    "account locked",
    "account disabled",
    "password required",
    "security check",
    "authentication required"
}

# Phrases that relate to finance / money
FINANCIAL_LANGUAGE = {
    "payment correction",
    "bank transfer",
    "wire fee",
    "overdue balance",
    "invoice attached",
    "pending invoice",
    "outstanding payment",
    "billing error",
    "payment issue",
    "transaction problem",
    "funds needed",
    "payment needed",
    "send payment",
    "gift card",
    "gift cards",
    "amazon card",
    "steam card",
    "itunes card",
    "google play card",
    "bitcoin",
    "crypto",
    "cryptocurrency",
    "btc",
    "ethereum",
    "western union",
    "moneygram",
    "wire transfer",
    "urgent transfer",
    "bank details",
    "routing number",
    "account number",
    "rent"
}

# Extensions considered to be risky
DANGEROUS_EXTENSIONS = {
    ".html",
    ".htm",
    ".xlsb",
    ".js",
    ".scr",
    ".exe",
    ".bat",
    ".vbs",
    ".cmd",
    ".jar",
    ".ps1"
}

# Expected extension / mime pairs
EXPECTED_MIME_MAP = {
    # Documents
    "pdf":  "application/pdf",
    "txt":  "text/plain",
    "rtf":  "application/rtf",

    # Word
    "doc":  "application/msword",
    "dot":  "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "docm": "application/vnd.ms-word.document.macroEnabled.12",

    # Excel
    "xls":  "application/vnd.ms-excel",
    "xlt":  "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    "xlsb": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",

    # PowerPoint
    "ppt":  "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.12",

    # OpenDocument
    "odt":  "application/vnd.oasis.opendocument.text",
    "ods":  "application/vnd.oasis.opendocument.spreadsheet",
    "odp":  "application/vnd.oasis.opendocument.presentation",

    # Images
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
    "png":  "image/png",
    "gif":  "image/gif",
    "bmp":  "image/bmp",
    "tif":  "image/tiff",
    "tiff": "image/tiff",
    "svg":  "image/svg+xml",
    "webp": "image/webp",

    # Audio
    "mp3":  "audio/mpeg",
    "wav":  "audio/wav",
    "ogg":  "audio/ogg",
    "flac": "audio/flac",
    "aac":  "audio/aac",

    # Video
    "mp4":  "video/mp4",
    "mov":  "video/quicktime",
    "wmv":  "video/x-ms-wmv",
    "avi":  "video/x-msvideo",
    "mkv":  "video/x-matroska",
    "webm": "video/webm",

    # HTML / Web
    "html": "text/html",
    "htm":  "text/html",
    "xml":  "application/xml",
    "json": "application/json",
    "js":   "application/javascript",
    "css":  "text/css",

    # Archives
    "zip":  "application/zip",
    "rar":  "application/x-rar-compressed",
    "7z":   "application/x-7z-compressed",
    "gz":   "application/gzip",
    "tar":  "application/x-tar",
    "bz2":  "application/x-bzip2",

    # Executables / Scripts
    "exe":  "application/x-msdownload",
    "dll":  "application/x-msdownload",
    "msi":  "application/x-msi",
    "bat":  "application/x-msdos-program",
    "cmd":  "application/cmd",
    "ps1":  "text/plain",
    "vbs":  "text/vbscript",
    "js":   "application/javascript",
    "jar":  "application/java-archive",
    "sh":   "text/plain",
    "py":   "text/x-python",

    # Email / Calendar
    "eml":  "message/rfc822",
    "ics":  "text/calendar"
}

"""
get_urgent_language

returns matches from the URGENT_LANGUAGE list
"""
def get_urgent_language(text):
    matches = []
    for term in URGENT_LANGUAGE:
        if term in text.lower():
            matches.append(term)
    return matches

"""
get_credential_language

returns matches from the CREDENTIAL_LANGUAGE list
"""
def get_credential_language(text):
    matches = []
    for term in CREDENTIAL_LANGUAGE:
        if term in text.lower():
            matches.append(term)
    return matches

"""
get_financial_language

returns matches from the FINANCIAL_LANGUAGE list
"""
def get_financial_language(text):
    matches = []
    for term in FINANCIAL_LANGUAGE:
        if term in text.lower():
            matches.append(term)
    return matches

"""
has_dangerous_extension

returns true if extension is in DANGEROUS_EXTENSIONS
"""
def has_dangerous_extension(extension):
    if extension in DANGEROUS_EXTENSIONS:
        return True
    return False

"""
has_mismatched_mime

returns true if mime doesn't match the one we expect
for the extension.
"""
def has_mismatched_mime(extension, mime):
    if extension in EXPECTED_MIME_MAP:
        return EXPECTED_MIME_MAP[extension] != mime
    return False