"""
geolocator.py

This geolocates ips
"""

import requests

"""
geolocate_ips

Returns a list of identified locations based on a list of ips

Uses ip-api.com
"""
def geolocate_ips(ip_list):
    locations = []
    for ip in ip_list:
        # URL is ip-api.com with the ip set to current ip
        url = f"http://ip-api.com/json/{ip}"
        try:
            response = requests.get(url, timeout=5)
            data = response.json()
            # Once response received, add the location
            if data["status"] == "success":
                locations.append({
                    "ip": ip,
                    "city": data.get("city", "N/A"),
                    "region": data.get("regionName", "N/A"),
                    "country": data.get("country", "N/A")
                })
            else:
                # No successful response, return placeholders
                locations.append({"ip": ip, "city": "N/A", "region": "N/A", "country": "N/A"})
        except Exception as e:
            #Failed API request, return placeholders
            locations.append({"ip": ip, "city": "N/A", "region": "N/A", "country": "N/A"})
    return locations