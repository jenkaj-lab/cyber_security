# Example Hashes:
# c0202cf6aeab8437c638533d14563d35 - LevelBlue
# 9ED866E14BB54406C075929183524039AB851A25 - Internet Explorer
# F08509DED34DD30349C2410820C1DD6DC4B36935 - New_order.exe

import sys, requests, json

# On a free plan you can make up to 500 requests per day.
VIRUSTOTAL_API_KEY = "bcb8bd677b2c218c40b78f1fc5a93c4c912a15ddca77fe33a077968bb609f83b"
#FILE = "writeup"
PREFIX = "    - "

def convert_list_to_string(list):
    return ", ".join(list)

def get_sandbox_verdicts(scan_results: list, data):
    # Currently this is working by making a list of lists, which need to be broken down and stored
    # as a singular string. This is why there are so many for loops.
    
    if "sandbox_verdicts" in data:
        classification_lists = []
        classifications = []
        
        # Get all malware classifications out of the sandbox verdicts in a list
        for sandbox, classification in data["sandbox_verdicts"].items():
            classification_lists.append(classification.get("malware_classification"))
    
        # Split the list of lists
        for classification_list in classification_lists:
            # Split the nested list
            for classification in classification_list:
                # Avoid adding duplicates
                if not classification in classifications:
                    # Add the result to the classifications
                    classifications.append(classification)
                    
        # If classifications were found, add them to the scan results
        if classifications:
            classifications_string = convert_list_to_string(classifications)
            scan_results.append(f"Sandbox Verdicts: {classifications_string}")
            
def get_threat_categories(data):
    """
    Example data:
    "popular_threat_category": [
      { "value": "ransomware", "count": 32 },
      { "value": "trojan", "count": 23 }
    ],
    """
    
    categories = []
    for category in data:
        categories.append(category["value"])
    return  f"- Threat Categories: {convert_list_to_string(categories)}"

def get_threat_names(data):
    """
    Example data:
    "popular_threat_name": [
      { "value": "ryuk", "count": 19 },
      { "value": "hermez", "count": 5 },
      { "value": "ransomx", "count": 2 }
    ]
    """
    
    threat_names = []
    for threat_name in data:
        threat_names.append(threat_name["value"])
    return f"- Threat Names: {convert_list_to_string(threat_names)}"

def get_packers(scan_results,attributes):
    if "packers" in attributes:
        packers = attributes["packers"]
        detections = len(packers)
        scan_results.append(f"- Packed file. Detected by {detections} sources.")


def print_hashes(scan_results,attributes):
    hash_type = ""
    hash_value = ""
    if "md5" in attributes:
        hash_type = "MD5"
        hash_value = attributes["md5"]
    scan_results.append("[*] Hashes:")
    scan_results.append(f"  - {hash_type}: {hash_value}")


def extract_signature_info(scan_results,data):
    extracted_info = {}
    extracted_info["Original Name"] = data.get("original name", None)
    extracted_info["Product"] = data.get("product", None)
    extracted_info["Description"] = data.get("description", None)
    extracted_info["Verified"] = data.get(
        "verified", None
    )  # Determine if file is signed
    extracted_info["Signers"] = data.get("signers", None)
    extracted_info["Signing Date"] = data.get("signing date", None)
    extracted_info["Version"] = data.get("file version", None)
    extracted_info["Copyright"] = data.get("copyright", None)

    for key, value in extracted_info.items():
        if value != None:
            scan_results.append(f"{PREFIX}{key}: {value}\n")


def malicious_writeup(last_analysis_stats):
    pass


def benign_writeup():
    pass


def check_plural(value, single, plural):
    # A bit of a novel function that just helps with readability
    if value != 1:
        return plural
    else:
        return single


def check_if_malicious(scan_results,data):
    last_analysis_stats = data["last_analysis_stats"]
    malicious_totals = last_analysis_stats["malicious"]
    suspicious_totals = last_analysis_stats["suspicious"]
    undetected_totals = last_analysis_stats["undetected"]

    if malicious_totals > 0:
        modifier = check_plural(malicious_totals, "Time", "Times")
        scan_results.append(f"{PREFIX}Flagged as malicious {malicious_totals} {modifier}")
    pass


def hash_lookup(hash):
    scan_results = []
    #hash = sys.argv[1]
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    decoded_response = response.json()
    if "error" in decoded_response:
        scan_results.append(decoded_response["error"]["message"])
        return scan_results
    attributes = decoded_response["data"]["attributes"]

    # Statistics
    last_analysis_stats = attributes["last_analysis_stats"]
    malicious_totals = last_analysis_stats["malicious"]
    suspicious_totals = last_analysis_stats["suspicious"]
    undetected_totals = last_analysis_stats["undetected"]

    if "signature_info" in attributes:
        extract_signature_info(scan_results,attributes["signature_info"])

    # formatted_json = json.dumps(decoded_response, indent=4)

    # with open(FILE, "a") as file:
    #    file.write(formatted_json)

    # Links
    links = decoded_response["data"]["links"]
    virustotal_link = links["self"]

    # Attributes

    reputation = attributes["reputation"]
    meaningful_name = attributes["meaningful_name"]
    
    if "popular_threat_classification" in attributes:
        threat_classification = attributes["popular_threat_classification"]
        if "popular_threat_category" in threat_classification:
            threat_category = threat_classification["popular_threat_category"]    
        scan_results.append(get_threat_names(threat_name))
        if "popular_threat_category" in threat_classification:
            threat_name = threat_classification["popular_threat_name"]
            scan_results.append(get_threat_categories(threat_category))

    # Analysis Stats

    # Threat Classifications
    print(json.dumps(attributes))
    # popular_threat_classification = attributes["popular_threat_classification"]
    # suggested_threat_label = popular_threat_classification["suggested_threat_label"]

    scan_results.append(f"[*] Scan results for {hash}")
    scan_results.append(f"{PREFIX}Registered name: {meaningful_name}")
    print_hashes(scan_results, attributes)
    
    # GET MALWARE CLASSIFICATIONS FROM SANDBOX
    get_sandbox_verdicts(scan_results,attributes)
    
    check_if_malicious(scan_results,attributes)


    get_packers(scan_results,attributes)
    #scan_results.append(f"[*] ")
    scan_results.append(
        f"This file has been flagged as malicious by {malicious_totals} security vendors, and suspicious by {suspicious_totals}."
    )
    # scan_results.append(f"Classified as: {suggested_threat_label}. With a reputation of {reputation}")
    scan_results.append(f"Reference: {virustotal_link}")
    
    return scan_results