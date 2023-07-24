import restfly.errors
import requests
from tenable.io import TenableIO
from config.config import APIkeys


tio = TenableIO(APIkeys.accessKey,
                APIkeys.secretKey, vendor='',  # edit required
                product='Log4j Remediation', build='1.0.0')
vulnerability_string = 'Log4j'
vulnerability_list = []
target_ipv4 = ''  # edit required


class Header:

    ACCEPT = '"accept": "application/json"'

    def __init__(self, url, access_key, secret_key):
        self._url = url
        self._access_key = access_key
        self._secret_key = secret_key

    @property
    def access_key(self):
        return self._access_key

    @property
    def secret_key(self):
        return self._secret_key

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, new_endpoint):
        if isinstance(new_endpoint, str) and "https://cloud.tenable.com/" in new_endpoint:
            self._url += new_endpoint

    def __str__(self):
        return f"{self.ACCEPT}, 'X-ApiKeys': 'accessKey={self._access_key};secretKey={self._secret_key}'"

    def asdict(self):
        return {'accept': "application/json", 'X-ApiKeys': f'accessKey={self._access_key};secretKey={self._secret_key}'}


def get_target_uuid():
    asset_uuid = []

    for asset in tio.assets.list():
        tenable_agent_id = asset['id']
        tenable_agent_discovered_ipv4 = asset['ipv4']
        if target_ipv4 in tenable_agent_discovered_ipv4:
            if '' in target_ipv4:  # edit required
                asset_uuid.append(tenable_agent_id)
                return asset_uuid
            else:
                print("[+] ERROR: " + target_ipv4 + " is not a valid IPv4 address")


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
    scanner_header = Header("https://cloud.tenable.com/scans/remediation", APIkeys.accessKey, APIkeys.secretKey)
    req = requests.get(scanner_header.url, headers=scanner_header.asdict())
    response = req.json()
    for i in response['scans']:
        if '' in i['owner']:  # edit required
            return i['id'], {i['owner']: i['name']}


def list_templates():
    uuids = []
    list_template_header = Header("https://cloud.tenable.com/editor/scan/templates", APIkeys.accessKey, 
                                  APIkeys.secretKey)
    req = requests.get(list_template_header.url, headers=list_template_header.asdict())
    response = req.json()
    for i in response['templates']:
        if 'Log4j' in i['desc']:  # edit required
            uuids.append(i['uuid'])
    return uuids


def remediation_scan(uuid):
    scanner_result = get_scanners()
    scan_name = ''
    url = "https://cloud.tenable.com/scans/remediation"
    scan_dict = scanner_result[1]
    for key in scan_dict:
        scan_name = (scan_dict[key])
    payload = {
        "settings": {
            "name": scan_name,
            "description": "Remediation scan created by <>'s Sentinel/Python automation",  # edit required
            "scanner_id": scanner_result[0]
        },
        # TODO: Fix UUID format. Current error: "Invalid 'uuid' for a remediation scan". \
        #  https://developer.tenable.com/reference/editor-list-templates
        "uuid": uuid
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={APIkeys.accessKey};secretKey={APIkeys.secretKey}"
    }

    response = requests.post(url, json=payload, headers=headers)

    # TODO: Change to a return after verified working
    print(response.text)


def main():
    try:
        scanner_response = get_scanners()
        print(scanner_response)
    except restfly.errors.GatewayTimeoutError as gateway:
        print("[+] HTTP 504: Gateway timeout: " + str(gateway))


# uuids = list_templates()
#
# for i in uuids:
#     remediation_scan(i)
#     print(i)

print(list_templates())
