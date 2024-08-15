import requests

def scan_website(url, api_key):
    # Define the URL for VirusTotal API
    vt_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    
    # Set up the parameters for the API request
    params = {'apikey': api_key, 'url': url}
    
    # Make the request to scan the URL
    response = requests.post(vt_url, data=params)
    
    # Check if the request was successful
    if response.status_code == 200:
        result = response.json()
        scan_id = result.get("scan_id")
        print(f"Scan ID: {scan_id}")
        
        # Get the report using the scan ID
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"
        report_params = {'apikey': api_key, 'resource': scan_id}
        report_response = requests.get(report_url, params=report_params)
        
        if report_response.status_code == 200:
            report = report_response.json()
            if report['response_code'] == 1:
                print(f"Scan Results for {url}:")
                print(f"Positives: {report['positives']}")
                print(f"Total Scans: {report['total']}")
                print(f"Scan Date: {report['scan_date']}")
            else:
                print("No scan results available yet.")
        else:
            print(f"Failed to get the report: {report_response.status_code}")
    else:
        print(f"Failed to scan the URL: {response.status_code}")

# Example Usage
api_key = 'Your API key'
website_url = 'htttps://example.com/'
scan_website(website_url, api_key)
