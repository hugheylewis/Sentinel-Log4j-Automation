# TODO: If committing to GitHub, add "config/.env" in your .gitignore to prevent committing/pushing API keys
import restfly.errors
from tenable.io import TenableIO
from config.config import APIkeys
import requests

tio = TenableIO(APIkeys.accessKey,
                APIkeys.secretKey, vendor='University of '
                                          'Massachusetts Boston',
                product='Log4j Remediation', build='1.0.0')
vulnerability_string = 'Nessus'
vulnerability_list = []
target_ipv4 = '158.121.114.45'


def get_target_uuid():
    asset_uuid = []

    for asset in tio.assets.list():
        tenable_agent_id = asset['id']
        tenable_agent_discovered_ipv4 = asset['ipv4']
        if target_ipv4 in tenable_agent_discovered_ipv4:
            if '158.121' in target_ipv4:
                asset_uuid.append(tenable_agent_id)
                print(asset_uuid)
                return asset_uuid
            else:
                print("[+] ERROR: " + target_ipv4 + " is not a valid UMB IPv4 address")


def get_target_vuln_list():
    for uuid in get_target_uuid():
        for vuln in tio.workbenches.asset_vulns(uuid):
            log4j_vuln = vuln['plugin_name']  # Unpacks dictionary key into a string
            if vulnerability_string in log4j_vuln:
                vulnerability_list.append(log4j_vuln)
                for i in vulnerability_list:
                    print(i)
            else:
                print("[+] Vulnerability " + '"' + log4j_vuln + '"' + " does not relate to Log4j.\nSkipping...")


def get_scanners():
    url = "https://cloud.tenable.com/scans"
    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={APIkeys.accessKey};secretKey={APIkeys.secretKey}"
    }
    req = requests.get(url, headers=headers)
    response = req.json()

    # TODO: Fix the API parsed response (currently returns None)
    for i in response['scans']:
        if 'cameron.hughey@umb.edu' in i['owner']:
            print(i['name'])


def remediation_scan(target):
    """

    :param target:
    :return:
    """
    for uuid in get_target_uuid():
        scan = tio.remediationscans.create_remediation_scan(
            _uuid=uuid,
            name='Log4j Remediation Scan - API Generated',
            description="Remediation scan created by Cam H's Sentinel/Python automation",
            #TODO: Finish get_scanners and add value below
            scanner_id='',
            scan_time_window=10,
            targets=['127.0.0.1:3000'],
            template='advanced')


def main():
    try:
        scanner_response = get_scanners()
        print(scanner_response)
    except restfly.errors.GatewayTimeoutError as gateway:
        print("[+] HTTP 504: Gateway timeout: " + str(gateway))


main()

# directory = input("Enter the directory: ")
