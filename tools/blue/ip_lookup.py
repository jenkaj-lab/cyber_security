# Check the reputation of any blacklists. Useful for SOC writeups.
# Usage: python3 {file_name}.py {ip_address}

ABUSE_IPDB_API_KEY = (
    # https://www.abuseipdb.com/
    ""
)

IPDATA_API_KEY = (
    # https://ipdata.co/
    ""
)

IPINFO_ACCESS_TOKEN = (
    # https://ipinfo.io/
    ""
)

import requests, json, sys, re


def scan_ip(ip):
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

    return format_data(unformatted_data)


def get_data(url, parameters, headers=None):

    encoded_response = requests.request(
        method="GET",
        url=url,
        params=parameters,
        headers=headers,
    )

    decoded_response = json.loads(encoded_response.text)

    return decoded_response


def format_data(unformatted_data):

    formatted_data = {}

    for data in unformatted_data:

        if "abuse_ipdb" in data:
            working_data = data["abuse_ipdb"]["data"]
            formatted_data["domain"] = working_data["domain"]
            formatted_data["isp"] = working_data["isp"]
            formatted_data["public"] = working_data["isPublic"]
            formatted_data["whitelisted"] = working_data["isWhitelisted"]
            formatted_data["confidence"] = working_data["abuseConfidenceScore"]
            formatted_data["usage"] = working_data["usageType"]
            formatted_data["tor_node"] = working_data["isTor"]
            formatted_data["abuse_reports"] = working_data["totalReports"]
            if not formatted_data['public']:
                return formatted_data

        elif "ipdata" in data:
            working_data = data["ipdata"]
            formatted_data["icloud_relay"] = working_data["is_icloud_relay"]
            formatted_data["proxy"] = working_data["is_proxy"]
            formatted_data["known_attacker"] = working_data["is_known_attacker"]
            formatted_data["known_abuser"] = working_data["is_known_abuser"]
            formatted_data["known_threat"] = working_data["is_threat"]
            formatted_data["bogon"] = working_data["is_bogon"]
            formatted_data["blocklists"] = working_data["blocklists"]

        elif "ipinfo" in data:
            working_data = data["ipinfo"]
            formatted_data["city"] = working_data["city"]
            formatted_data["region"] = working_data["region"]
            formatted_data["country"] = working_data["country"]

    return formatted_data


def check_plural(value, single, plural):
    if value != 1:
        return plural
    else:
        return single


def check_total_abuse_reports(abuse_reports):
    modifier = check_plural(abuse_reports, "time", "times")
    if abuse_reports > 0:
        print(f"[*] Reported as abusive {abuse_reports} {modifier}")


def assess_abuse_confidence(abuse_reports, confidence):
    if confidence >= 50:
        print(f"[*] High probability this address is malicious ({confidence}%)")
    elif confidence >= 25:
        print(f"[*] Moderate probability this address is malicious ({confidence}%)")
    else:
        print(f"[*] Low probability this address is malicious ({confidence}%)")
    check_total_abuse_reports(abuse_reports)


def defang(domain):
    defanged_domain = re.sub(r"\.", "[.]", domain)
    return defanged_domain


def single_scan(ip_address):

    data = scan_ip(ip_address)
    public_address = data["public"]
    print(f"[*] Address: {ip_address}")

    if public_address:

        defanged_domain = defang(data["domain"])
        usage_type = data["usage"]
        isp = data["isp"]
        city = data["city"]
        region = data["region"]
        country = data["country"]

        print(f"[*] Domain: {defanged_domain}")
        print(f"[*] ISP: {isp} ({usage_type})")
        print(f"[*] Location: {city}, {region}. {country}.")

        abuse_reports = data["abuse_reports"]
        confidence = data["confidence"]
        whitelisted = data["whitelisted"]
        tor_node = data["tor_node"]
        known_attacker = data["known_attacker"]
        known_abuser = data["known_abuser"]
        known_threat = data["known_threat"]
        bogon = data["bogon"]
        blocklists = data["blocklists"]
        icloud_relay = data["icloud_relay"]
        proxy = data["proxy"]

        if tor_node:
            print("[*] Known TOR node")

        if icloud_relay:
            print("[*] Known iCloud relay")

        if proxy:
            print("[*] Known proxy")

        # Check to see if the address is whitelisted before doing an abuse check
        if whitelisted:
            print("[*] Whitelisted address")
        else:
            # Determine if the address is abusive
            if known_abuser or known_threat or known_attacker or confidence >= 75:
                print("[*] Known malicious address")
                check_total_abuse_reports(abuse_reports)
            else:
                if confidence > 0:
                    assess_abuse_confidence(abuse_reports, confidence)
                else:
                    print("[*] Non-malicious")

            # Check to see if the address is illegitimate (not officially assigned by an internet registration institute)
            if bogon:
                print("[*] Unallocated IP address (bogon)")

            # Check to see if the address is in any blocklists (ipdata_data.co)
            # Could be good to add a list of blocklists here to scan directly from the directory
            if blocklists:
                blocklist_count = len(blocklists)
                modifier = check_plural(blocklist_count, "blocklist", "blocklists")
                print(f"[*] Appeared in {blocklist_count} {modifier}")
    else:
        print(f"[*] Private/reserved address")


def main():

    input = sys.argv[1]
    ip_addresses = input.split(',')

    for ip in ip_addresses:
        single_scan(ip)
        
    #if len(ip_addresses) > 1:
        # multi_scan(ip_address)
    #else:
        #single_scan(ip_address)


main()
