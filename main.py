"""
main.py

The main file for the email analyzer project. Identifies .eml files and
starts up report generation.
"""

from eml_ingest import *
from geolocator import *
from report_generator import *

def main():
    eml_files = list_eml_files()
    if not eml_files:
        return
    
    for email in eml_files:
        header = parse_header(email)
        received_list = header["Received"]
        ips = extract_hop_ips(received_list)
        locations = geolocate_ips(ips)
        generate_report(header, locations, email)
        # print(extract_body(email))

if __name__ == "__main__":
    main()