"""
geolocator.py

This generates the report on the eml file
"""

import os
from eml_ingest import *
from url_analyzer import *
from text_analyzer import *
from header_analyzer import *

WEIGHT_SUS_TLD              = 3
WEIGHT_IP_DOMAIN            = 5
WEIGHT_LONG_URL             = 1
WEIGHT_LANG_URGENT          = 2
WEIGHT_LANG_CREDENTIAL      = 4
WEIGHT_LANG_FINANCIAL       = 5
WEIGHT_ATTCH_EXT            = 5
WEIGHT_ATTCH_MIME_MISMATCH  = 10
WEIGHT_FOREIGN_HOP          = 5
WEIGHT_FROM_REPLY_MISMATCH  = 6

def generate_report(header, locations, eml_filename):
    count_suspicious_tld = 0
    count_ip_as_domain = 0
    count_long_url = 0
    count_language_urgent = 0
    count_language_credential = 0
    count_language_financial = 0
    count_attachment_extension = 0
    count_attachment_mime_mismatch = 0
    count_foreign_hop = 0
    count_from_reply_mismatch = 0
   
    os.makedirs("reports", exist_ok=True)

    #Make report name based on eml file name
    #get everything between the path and the extension, just the actual file name
    base_filename = os.path.splitext(os.path.basename(eml_filename))[0]
    #use that to make report file name
    report_filename = base_filename + "_report.txt"
    report_filepath = os.path.join("reports", report_filename)

    #Write the report
    with open(report_filepath, "w", encoding="utf-8") as report_file:
        report_file.write("-------------------- EMAIL ANALYSIS REPORT --------------------\n\n")
        report_file.write(f"From: {header['From']}\n")
        report_file.write(f"To: {header['To']}\n")
        report_file.write(f"Reply-To: {header['Reply-To']}\n")
        report_file.write(f"Subject: {header['Subject']}\n")
        report_file.write(f"Date: {header['Date']}\n\n")

        # Check From Vs Reply-To
        if has_from_replyTo_mismatch(header):
            count_from_reply_mismatch = 1
            report_file.write("Detected a mismatch between From and Reply-To\n\n")

        # Analysis of hops
        if locations:
            report_file.write("Identified hops:\n\n")
            # use reversed so that the report gives hops in chronological order
            for i, location in enumerate(reversed(locations), start=1):
                city = location['city']
                region = location['region']
                country = location['country']
                ip = location['ip']
                ip_classification = get_ip_classification(ip)

                if ip_classification == "Invalid":
                    continue
                elif ip_classification == "Loopback" or ip_classification == "Private":
                    report_file.write(f"Hop {i}: ({ip} - Classification: {ip_classification}) - No location data for internal IP addresses\n\n")
                else:
                    report_file.write(f"Hop {i}: ({ip} - Classification: {ip_classification}) - {city}, {region}, {country}\n")
                    if country != "United States":
                        count_foreign_hop += 1
                        report_file.write("Detected hop was outside of the United States\n")
                    report_file.write("\n")
                    

        # Extract body
        body_contents = extract_body(eml_filename)
        
        # Analysis of URLs
        urls = extract_urls(body_contents)

        #test
        #urls.append("http://185.224.12.55/login")
        #urls.append("thisisascam.shop")

        url_is_sus = False
        if urls:
            report_file.write("Identified URLs:\n")
            for url in urls:
                report_file.write("\n"+url+"\nDetections: ")
                if is_raw_ip(url):
                    count_ip_as_domain += 1
                    url_is_sus = True
                    report_file.write("(Raw IP) ")
                if has_suspicious_tld(url):
                    count_suspicious_tld += 1
                    url_is_sus = True
                    report_file.write("(Suspicious TLD) ")
                if is_very_long(url):
                    count_long_url += 1
                    url_is_sus = True
                    report_file.write("(Excessively long)")
                if not url_is_sus:
                    report_file.write("Nothing suspicious detected.")
                else:
                    url_is_sus = False
                report_file.write("\n")
            report_file.write("\n")
                

        # Analysis of body
        language_urgent = get_urgent_language(body_contents)
        language_credential = get_credential_language(body_contents)
        language_financial = get_financial_language(body_contents)

        count_language_urgent = len(language_urgent)
        count_language_credential = len(language_credential)
        count_language_financial = len(language_financial)

        if language_urgent:
            report_file.write(f"Identified urgency keyphrases: {language_urgent}\n\n")
        if language_credential:
            report_file.write(f"Identified credential keyphrases: {language_credential}\n\n")
        if language_financial:
            report_file.write(f"Identified financial keyphrases: {language_financial}\n\n")

        # Analysis of attachments
        attachments = extract_attachments(eml_filename)
        if attachments:
            report_file.write("Identified attachments:\n\n")
            for attachment in attachments:
                report_file.write(attachment["filename"]+"\n")
                if has_dangerous_extension(attachment["extension"]):
                    count_attachment_extension += 1
                    report_file.write("Risky extension detected\n")
                if has_mismatched_mime(attachment["extension"], attachment["mime"]):
                    count_attachment_mime_mismatch += 1
                    report_file.write("Extension-Mime mismatch detected\n")
                report_file.write("\n")

        # Determine numerical risk rating and decide severity
        risk_rating = (
            count_ip_as_domain*WEIGHT_IP_DOMAIN                         +
            count_suspicious_tld*WEIGHT_SUS_TLD                         +
            count_long_url*WEIGHT_LONG_URL                              +
            count_language_urgent*WEIGHT_LANG_URGENT                    +
            count_language_credential*WEIGHT_LANG_CREDENTIAL            +
            count_language_financial*WEIGHT_LANG_FINANCIAL              +
            count_attachment_extension*WEIGHT_ATTCH_EXT                 +
            count_attachment_mime_mismatch*WEIGHT_ATTCH_MIME_MISMATCH   +
            count_foreign_hop*WEIGHT_FOREIGN_HOP                        +
            count_from_reply_mismatch*WEIGHT_FROM_REPLY_MISMATCH
        )

        # Values are mostly arbitrary and could be tuned to liking
        if risk_rating >= 16:
            risk_grade = "HIGH RISK"
        elif risk_rating >= 8:
            risk_grade = "MODERATE RISK"
        else:
            risk_grade = "LOW RISK"


        report_file.write(f"Risk rating: {risk_rating} ({risk_grade})\n\n")

        # if body_contents:
        #     report_file.write("\nExtracted body contents:\n\n")
        #     report_file.write(body_contents)

        report_file.write("-------------------- EMAIL ANALYSIS REPORT --------------------")