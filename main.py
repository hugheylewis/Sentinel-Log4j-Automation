import json

import restfly.errors
import requests
from tenable.io import TenableIO
from config.config import APIkeys


tio = TenableIO(APIkeys.accessKey,
                APIkeys.secretKey, vendor='',  # edit required
                product='Log4j Remediation', build='1.0.0')
vulnerability_string = 'Log4j'
log4j_vuln_list = []
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
    get_target_header = Header("https://cloud.tenable.com/assets", APIkeys.accessKey, APIkeys.secretKey)
    req = requests.get(get_target_header.url, headers=get_target_header.asdict())
    response = req.text
    json_response = json.loads(response)

    for i in json_response['assets']:
        if "" in i['hostname']:  # add your hostname here
            asset_uuid.append(i['id'])
    return asset_uuid


def get_target_vuln_list():
    other_vuln_list = []
    for uuid in get_target_uuid():
        for vulnerability in tio.workbenches.asset_vulns(uuid):
            vuln_found = vulnerability['plugin_name']  # Unpacks dictionary key into a string
            if vulnerability_string in vuln_found:
                log4j_vuln_list.append(vuln_found)
            else:
                other_vuln_list.append(vuln_found)
    return other_vuln_list, log4j_vuln_list


def get_scanners():
    scanner_header = Header("https://cloud.tenable.com/scanners", APIkeys.accessKey, APIkeys.secretKey)
    req = requests.get(scanner_header.url, headers=scanner_header.asdict())
    response = req.json()
    print(response)
    for i in response:
        print(i)
        if '' in i['name']:  # add the owner name here
            return i['id'], {i['owner']: i['name']}


def list_templates():
    list_template_header = Header("https://cloud.tenable.com/scans", APIkeys.accessKey,
                                  APIkeys.secretKey)
    req = requests.get(list_template_header.url, headers=list_template_header.asdict())
    response = req.json()
    for i in response['scans']:
        if "" in i['name']:  # add the scan name here
            return i['schedule_uuid']


def launch_scan():
    launch_scan_header = Header("https://cloud.tenable.com/scans/", APIkeys.accessKey, APIkeys.secretKey)
    scan_template_id = list_templates()
    url = "https://cloud.tenable.com/scans/" + scan_template_id + "/launch"

    response = requests.post(url, headers=launch_scan_header.asdict())

    # TODO: Change to a return after verified working
    print(response.text)


def main():
    vuln_list = get_target_vuln_list()
    for i in vuln_list:
        print(i)
    # TODO: Fix the get_scanners() function
    # try:
    #     scanner_response = get_scanners()
    #     print(scanner_response)
    # except restfly.errors.GatewayTimeoutError as gateway:
    #     print("[+] HTTP 504: Gateway timeout: " + str(gateway))


if __name__ == "__main__":
    main()
