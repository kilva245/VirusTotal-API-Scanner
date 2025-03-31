import requests
import base64
import hashlib
# for set color to first text when run the script (for banner in basic header)
from colorama import init, Fore
# for banner in basic header
import pyfiglet

init()

#get api key from https://www.virustotal.com/gui/user/{yourUserName}/apikey
api_key = "be2e9da1871bd56cbb09c3a703cb12da1ced4236ad2eee1c0e6dd69a194ceb20"

# Basic user interface header
banner = pyfiglet.figlet_format("   kilva   ")
print(Fore.RED + banner)
print(Fore.RED + "\n****************************************************************")
print(Fore.RED + "\n*                  Copyright of kilva, 2025                    *")
print(Fore.RED + "\n****************************************************************")
print(Fore.RESET)  # Reset color to default

VT_URL = "https://www.virustotal.com/api/v3/"
VT_FILE_SCAN_URL = VT_URL + "files"
VT_HASH_SEARCH_URL = VT_URL + "files/"
VT_DOMAIN_SEARCH_URL = VT_URL + "domains/"
VT_URL_SCAN_URL = VT_URL + "urls"

#File hash calculation function
def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb")as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()


#for scanning file
def file_scan(file_path):
    headers = {"x-apikey": api_key}
    files = {"file": open(file_path, "rb")}
    response = requests.post(VT_FILE_SCAN_URL, headers=headers,files=files)
    
    if response.status_code == 200:
        scan_result = response.json()
        print(f"🔍 File uploaded successfully!\nScan ID: {scan_result['data']['id']}")
    else:
        print(f"❌ Error uploading file:", response.text)
        

#for search by hash function        
def search_by_hash(file_hash):
    headers = {"x-apikey": api_key}
    url = VT_HASH_SEARCH_URL + file_hash
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        if "data" in result:
            detection_stats = result["data"]["attributes"]["last_analysis_stats"]
            detections = result["data"]["attributes"]["last_analysis_results"]

            print(f"✅ Hash found!\nDetections: {detection_stats}")

            print("\n🔍 Detailed Results:")
            for engine, details in detections.items():
                result = details["category"]  
                print(f"🛡 {engine}: {result}")

        else:
            print("⚠️ Hash found but no analysis data available.")
    elif response.status_code == 404:
        print("❌ No results found for this hash. It might not be scanned yet.")
    else:
        print(f"❌ Error: {response.status_code}, {response.text}")

        
#for domain function
def check_domain(domain):
    headers = {"x-apikey": api_key}
    url = VT_DOMAIN_SEARCH_URL + domain
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()

        if "data" in result:
            attributes = result["data"]["attributes"]
            reputation = attributes.get("reputation", "N/A")
            category = attributes.get("categories", {})
            analysis = attributes.get("last_analysis_stats", {})
            detections = attributes.get("last_analysis_results", {})

            print(f"✅ Domain found: {domain}")
            print(f"🌟 Reputation: {reputation}")
            print(f"📌 Categories: {', '.join(category.values()) if category else 'Unknown'}")
            print(f"🔍 Analysis: {analysis}")

            print("\n🚨 Detailed Detections:")
            for engine, result in detections.items():
                if result["category"] in ["malicious", "suspicious"]:
                    print(f"🔴 {engine}: {result['category'].upper()} - {result.get('result', 'Unknown')}")
                else:
                    print(f"🟢 {engine}: {result['category'].capitalize()}")

        else:
            print("⚠️ Domain found but no analysis data available.")

    elif response.status_code == 404:
        print("❌ No results found for this domain. It might not be scanned yet.")
    else:
        print(f"❌ Error: {response.status_code}, {response.text}")



#check URL function
def check_url(url):
    headers = {"x-apikey": api_key}
    encoded_url = requests.utils.quote(url)
    response = requests.get(VT_URL_SCAN_URL + encoded_url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        data = result['data']
        url_info = data['attributes']

        print(f"🔍 URL Analysis for: {url}")
        print(f"🌟 Reputation: {url_info.get('reputation', 'N/A')}")
        print(f"📌 Categories: {', '.join(url_info.get('categories', []))}")
        print(f"🔍 Analysis: {url_info['last_analysis_stats']}")

        if "last_analysis_results" in url_info:
            print("\n🛡️ Detailed Analysis:")
            for engine, details in url_info["last_analysis_results"].items():
                print(f"Engine: {engine} - {details['category']} - {details.get('result', 'No result')}")
    else:
        print("❌ Error scanning URL:", response.text)
#Choose an option for the user
print("Choose an option:\n\n1️⃣ Scan a file\n2️⃣ Search by hash\n3️⃣ Check a domain\n4️⃣ Scan a URL")
choice = input("\n\nEnter 1, 2, 3 or 4: ")

if choice == "1":
    file_path = input("Enter file path: ")
    file_scan(file_path)
elif choice == "2":
    file_hash = input("Enter file hash (SHA256, MD5, SHA1): ")
    search_by_hash(file_hash)
elif choice == "3":
    domain = input("Enter domain: ")
    check_domain(domain)
elif choice == "4":
    url = input("Enter URL: ")
    check_url(url)
else: 
    print("❌ invalid choice!")
