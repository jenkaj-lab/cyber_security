# Check the reputation of IP addresses. Useful for SOC writeups.
# Comma separate values to scan multiple addresses at once.
# Usage: python3 {file_name}.py {address_1},{address_2}

ABUSE_IPDB_API_KEY = (
    # https://www.abuseipdb.com/
    # 1,000 lookups per day
    "CHANGEME"
)

IPDATA_API_KEY = (
    # https://ipdata.co/
    # 1,500 lookups per day
    "CHANGEME"
)

IPINFO_ACCESS_TOKEN = (
    # https://ipinfo.io/
    # 50,000 lookups per month
    "CHANGEME"
)

VPN_API_KEY = (
    # https://vpnapi.io/
    # 1,000 lookups per day
    "CHANGEME"
)

import requests, json, sys, re


def scan_ip(ip):
    # Append API responses to a list for sorting later on
    unformatted_data = []

    unformatted_data.append(
        {
            "abuse_ipdb": get_data(
                "https://api.abuseipdb.com/api/v2/check",
                {"ipAddress": ip},
                {"Accept": "application/json", "Key": ABUSE_IPDB_API_KEY},
            ),
        }
    )

    unformatted_data.append(
        {
            "ipdata": get_data(
                f"https://api.ipdata.co/{ip}/threat",
                {"api-key": IPDATA_API_KEY},
            ),
        }
    )

    unformatted_data.append(
        {
            "ipinfo": get_data(
                f"https://ipinfo.io/{ip}",
                {"token": IPINFO_ACCESS_TOKEN},
            ),
        }
    )

    unformatted_data.append(
        {
            "vpnapi": get_data(
                f"https://vpnapi.io/api/{ip}",
                {"key": VPN_API_KEY},
            )
        }
    )

    return format_data(unformatted_data)


def get_data(url, parameters, headers=None):
    # Headers is none by default because they may not always be required by the APIs
    encoded_response = requests.request(
        method="GET",
        url=url,
        params=parameters,
        headers=headers,
    )

    decoded_response = json.loads(encoded_response.text)

    return decoded_response


def format_data(unformatted_data):
    # Format the data into a structured dictionary for scalability
    formatted_data = {}
    formatted_data["tor_node"] = []
    formatted_data["vpn"] = []
    formatted_data["relay"] = []
    formatted_data["proxy"] = []

    for data in unformatted_data:

        if "abuse_ipdb" in data:

            working_data = data["abuse_ipdb"]["data"]
            formatted_data["public"] = working_data["isPublic"]

            # No further info is needed when IP is private so we can return early
            if not formatted_data["public"]:
                return formatted_data

            formatted_data["domain"] = working_data["domain"]
            formatted_data["isp"] = working_data["isp"]
            formatted_data["whitelisted"] = working_data["isWhitelisted"]
            formatted_data["confidence"] = working_data["abuseConfidenceScore"]
            formatted_data["usage"] = working_data["usageType"]
            formatted_data["abuse_reports"] = working_data["totalReports"]
            formatted_data["tor_node"].append(working_data["isTor"])

        elif "ipdata" in data:
            working_data = data["ipdata"]
            formatted_data["known_attacker"] = working_data["is_known_attacker"]
            formatted_data["known_abuser"] = working_data["is_known_abuser"]
            formatted_data["known_threat"] = working_data["is_threat"]
            formatted_data["bogon"] = working_data["is_bogon"]
            formatted_data["blocklists"] = working_data[
                "blocklists"
            ]  # can be removed in future
            formatted_data["tor_node"].append(working_data["is_tor"])
            formatted_data["relay"].append(working_data["is_icloud_relay"])
            formatted_data["proxy"].append(working_data["is_proxy"])

        elif "ipinfo" in data:
            working_data = data["ipinfo"]
            formatted_data["city"] = working_data["city"]
            formatted_data["region"] = working_data["region"]
            formatted_data["country"] = working_data["country"]

        elif "vpnapi" in data:
            working_data = data["vpnapi"]["security"]
            formatted_data["vpn"].append(working_data["vpn"])
            formatted_data["tor_node"].append(working_data["tor"])
            formatted_data["relay"].append(working_data["relay"])
            formatted_data["proxy"].append(working_data["proxy"])

    return formatted_data


def check_plural(value, single, plural):
    # A bit of a novel function that just helps with readability
    if value != 1:
        return plural
    else:
        return single


def check_total_abuse_reports(abuse_reports):
    modifier = check_plural(abuse_reports, "time", "times")
    if abuse_reports > 0:
        print(f"    - Reported {abuse_reports} {modifier} for abuse")


def assess_abuse_confidence(abuse_reports, confidence):
    # These values are personal preference
    # Note: 75%+ confidence is matched in the reputation check
    if confidence >= 50 and confidence < 75:
        print(f"    - High probability this address is abusive ({confidence}%)")
    elif confidence >= 25:
        print(f"    - Moderate probability this address is abusive ({confidence}%)")
    else:
        print(f"    - Low probability this address is abusive ({confidence}%)")
    check_total_abuse_reports(abuse_reports)


def defang(domain):
    defanged_domain = re.sub(r"\.", "[.]", domain)
    return defanged_domain


def check_if_true(list_of_items):
    for item in list_of_items:
        if item:
            return True
    return False


def get_detections(data):

    detections = []

    tor_node = check_if_true(data["tor_node"])
    icloud_relay = check_if_true(data["relay"])
    proxy = check_if_true(data["proxy"])
    vpn = check_if_true(data["vpn"])
    bogon = data["bogon"]

    if tor_node:
        detections.append("TOR Node")

    if icloud_relay:
        detections.append("Relay")

    if proxy:
        detections.append("Proxy")

    if vpn:
        detections.append("VPN")

    if bogon:
        # Check to see if the address is illegitimate (not officially assigned by an internet registration institute)
        detections.append("Bogon")

    return detections


def get_reputation(data, confidence):

    reputation = []

    known_attacker = data["known_attacker"]
    known_abuser = data["known_abuser"]
    known_threat = data["known_threat"]

    if known_abuser or confidence >= 75:
        reputation.append("Abusive")

    if known_attacker:
        reputation.append("Attacker")

    if known_threat:
        reputation.append("Threat")

    return reputation


def sort_blocklists(blocklists):

    formatted_blocklist = []

    for blocklist in blocklists:
        formatted_blocklist.append(blocklist["name"])

    return formatted_blocklist


def list_to_string(list):
    return ", ".join(list)


def lookup(ip_address):

    data = scan_ip(ip_address)
    public_address = data["public"]
    print(f"[*] Scan results for {ip_address}")

    if public_address:

        defanged_domain = defang(data["domain"])
        usage_type = data["usage"]
        isp = data["isp"]
        city = data["city"]
        region = data["region"]
        country = data["country"]

        print(f"    - Domain: {defanged_domain}")
        print(f"    - ISP: {isp} ({usage_type})")
        print(f"    - Location: {city}, {region}. {country}.")

        abuse_reports = data["abuse_reports"]
        confidence = data["confidence"]
        whitelisted = data["whitelisted"]
        blocklists = data["blocklists"]

        # Check to see if the address is whitelisted before doing an abuse check
        if whitelisted:
            print("    - Whitelisted address")

        else:

            detections = get_detections(data)
            if detections:
                modifier = check_plural(len(detections), "Detection", "Detections")
                formatted_detections = list_to_string(detections)
                print(f"    - {modifier}: {formatted_detections}")

            reputation = get_reputation(data, confidence)
            if reputation:
                formatted_reputation = list_to_string(reputation)
                print(f"    - Reputation: {formatted_reputation}")
                check_total_abuse_reports(abuse_reports)

            if blocklists:
                # Check to see if the address is in any blocklists on ipdata
                # Todo: Have the script scan a list of blacklists from a provided directory path
                modifier = check_plural(len(blocklists), "Blocklist", "Blocklists")
                stripped_blocklists = sort_blocklists(blocklists)
                formatted_blocklists = list_to_string(stripped_blocklists)
                print(f"    - {modifier}: {formatted_blocklists}")

            elif confidence > 0:
                assess_abuse_confidence(abuse_reports, confidence)

            else:
                print("    - Non-malicious")

    else:
        print(f"    - Private/reserved")


def main():

    input = sys.argv[1]
    ip_addresses = input.split(",")

    for ip in ip_addresses:
        lookup(ip)


main()
