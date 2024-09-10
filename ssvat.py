# SSVAT 1.0 - Simple System Vulnerability Assessment Tool
# Author: Logan Scott
# This script grabs latest CVE data from NIST NVD and compares it with installed software on the target system 
# to generate a simple HTML vulnerability report.

# NIST NVD API documentation
# https://nvd.nist.gov/developers/vulnerabilities
# https://nvd.nist.gov/developers/start-here

import requests
import subprocess
import json
import os
from datetime import datetime, timedelta
import socket
import logging

# Uncomment to enable debug logging
logging.basicConfig(level=logging.DEBUG)

#API_KEY = "e128553a-ba26-4bec-b3b6-3d0f0fdb4746"
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# HTTP GET request to fetch CVEs from NIST NVD
def get_cves(pubStartDate=None, pubEndDate=None):
    # get API key from file
    with open("nist_api_key", "r") as file:
        API_KEY = file.read().strip()
    
    headers = {
        "apikey": API_KEY
    }

    params = {
        "resultsPerPage": 100,  # Fetch 100 results at a time
        'startIndex': '0'  # Start from the first result
    }

    if pubStartDate:
        params['pubStartDate'] = pubStartDate
    if pubEndDate:
        params['pubEndDate'] = pubEndDate

    print("Fetching CVEs from NIST NVD...")
    try: 
        response = requests.get(CVE_URL, headers=headers, params=params)

        if response.status_code == 200:
            print("Successfully fetched CVEs!")
            return response.json()
        else:
            print(f"Failed to fetch CVEs. Status code: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
        return None

# Function to get a list of installed packages on the system
def get_installed_software():
    print("Fetching installed software...")
    
    installed_packages = {}
    
    # Debian/Ubuntu systems
    if os.path.exists("/usr/bin/dpkg"):
        try:
            result = subprocess.run(['dpkg', '-l'], stdout=subprocess.PIPE, text=True)
            for line in result.stdout.splitlines():
                if line.startswith("ii"):
                    parts = line.split()
                    package_name = parts[1]
                    #print("Package: " + package_name)
                    package_version = parts[2]
                    #print("Version: " + package_version)
                    installed_packages[package_name] = package_version
        except Exception as e:
            print(f"Error fetching installed packages (dpkg): {e}")
    
    # Red Hat/CentOS systems
    elif os.path.exists("/bin/rpm"):
        try:
            result = subprocess.run(['rpm', '-qa'], stdout=subprocess.PIPE, text=True)
            for line in result.stdout.splitlines():
                parts = line.split("-")
                package_name = parts[0]
                package_version = "-".join(parts[1:])
                installed_packages[package_name] = package_version
        except Exception as e:
            print(f"Error fetching installed packages (rpm): {e}")
    
    print(f"Found {len(installed_packages)} installed packages.")
    return installed_packages

# Function to compare installed software with CVEs
def compare_cves_with_installed_software(cve_data, installed_software):
    vulnerable_software = []
    
    for cve_item in cve_data.get('result', {}).get('CVE_Items', []):
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        description = cve_item['cve']['description']['description_data'][0]['value']
        affected_products = cve_item['configurations']['nodes']
        
        for node in affected_products:
            for match in node.get('cpe_match', []):
                vulnerable_package = match['cpe23Uri'].split(":")[4]
                vulnerable_version = match['cpe23Uri'].split(":")[5]
                
                # Check if the package is installed
                if vulnerable_package in installed_software:
                    installed_version = installed_software[vulnerable_package]
                    
                    if installed_version == vulnerable_version:
                        vulnerable_software.append({
                            'cve_id': cve_id,
                            'package': vulnerable_package,
                            'installed_version': installed_version,
                            'description': description
                        })
    
    return vulnerable_software

# generate HTML report of vulnerable software
def generate_html_report(vulnerable_software, installed_software, cve_list):
    hostname = os.uname().nodename
    network_hostname = socket.gethostname()
    host_ip = socket.gethostbyname(network_hostname)

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_content = f"<html><head><title>Vulnerability Report</title></head><body>"
    report_content += f"<h1>{hostname} - Vulnerability Report - {report_time}</h1>"
    
    if not vulnerable_software:
        report_content += "<p>No vulnerable software detected.</p>"
    else:
        report_content += "<ul>"
        for vuln in vulnerable_software:
            report_content += f"<li><strong>CVE:</strong> {vuln['cve_id']}<br>"
            report_content += f"<strong>Package:</strong> {vuln['package']}<br>"
            report_content += f"<strong>Installed Version:</strong> {vuln['installed_version']}<br>"
            report_content += f"<strong>Description:</strong> {vuln['description']}<br></li><br>"
        report_content += "</ul>"
    
    # append a list of fetched CVEs at the bottom of the report
    report_content += "<h2>List of Checked CVEs</h2>"
    report_content += "<ul>"

    if "vulnerabilities" in cve_list:
        for vuln in cve_list["vulnerabilities"]:
            cve_id =vuln["cve"]["id"]
            description = vuln["cve"]["descriptions"][0]["value"]
            report_content += f"<li><strong>{cve_id}</strong>: {description}</li>\n"
    else:
        report_content += "<li>No CVEs in response.</li>\n"

    report_content += "</ul>"

    # append a list of installed software at the bottom of the report
    report_content += "<h2>List of Installed Software</h2>"
    report_content += "<ul>"
    for package, version in installed_software.items():
        report_content += f"<li>{package}: {version}</li>"
    report_content += "</ul>"

    report_content += "</body></html>" # end of HTML content
    
    # write report to file
    report_time = report_time.split(" ")[0]
    report_filename = f"{hostname}_vulnerability_report_{report_time}.html"
    with open(report_filename, "w") as report_file:
        report_file.write(report_content)
   
    print("HTML report generated: %s" % (report_filename))

# Main program
if __name__ == "__main__":
    print("Starting SSVAT...")
    
    # Per NIST documenation: "The maximum allowable range when using any date range parameters is 120 consecutive days."
    # Values must be entered in the extended ISO-8601 date/time format:[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]

    # Usage "python3 cve_scan.py <timeframe>" where timeframe is the number of months back to check for CVEs
    # If no timeframe is provided (e.g. "python3 cve_scan.py"), default is 4 months
    #timeframe = int(input(f"Enter how many months back to check for CVEs (default is 4): "))

    if len(os.sys.argv) > 1:
        try:
            days = int(os.sys.argv[1])
        except:
            print("Invalid input, using default max timeframe of 120 days.")
            days = 120
    else:
        print("Using default max timeframe of 120 days.")
        days = 120
            
    pubStartDate = (datetime.now() - timedelta(days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pubEndDate = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    print(f"Checking for CVEs published after {pubStartDate}")

    # Fetch CVE data from NIST NVD
    cve_data = get_cves(pubStartDate=pubStartDate, pubEndDate=pubEndDate)

    if cve_data:
        installed_software = get_installed_software()
        vulnerable_software = compare_cves_with_installed_software(cve_data, installed_software)
        generate_html_report(vulnerable_software, installed_software, cve_data)
    else:
        print("Failed to retrieve CVE data. Exiting.")
