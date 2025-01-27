# Copyright (c) 2024 STORDIS GmbH. All rights reserved.
# This code is the property of STORDIS GmbH and can not be redistributed without the written permission of STORDIS GmbH.
from enum import Enum
import base64
import json
 
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
 
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
 
username = "admin"
password = "YourPaSsWoRd"
device_ip_list = ["10.10.229.171", "10.10.229.51", "10.10.229.52"]
 
auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
headers = {
    "Authorization": f"Basic {auth_string}",
    "Content-Type": "application/yang-data+json",
}
 
## Enum for http requests
class HttpRequest(Enum):
    GET = "GET"
    PUT = "PUT"
    POST = "POST"
    PATCH = "PATCH"
    DELETE = "DELETE"
 
 
def send_req(req: HttpRequest, resource_url, req_body=None, timeout_sec=5):
    response = None
    switch_case = {
        HttpRequest.GET: requests.get,
        HttpRequest.PUT: requests.put,
        HttpRequest.POST: requests.post,
        HttpRequest.PATCH: requests.patch,
        HttpRequest.DELETE: requests.delete,
    }
    try:
        response = switch_case.get(
            req, lambda: print("Invalid request type: {0}".format(req))
        )(
            resource_url,
            verify=False,
            headers=headers,
            json=req_body,
            timeout=timeout_sec,
        )
    except requests.exceptions.Timeout as e:
        print(e)
    except requests.exceptions.RequestException as e:
        print(e)
    # parse resource_url and print only the IP
    ip = resource_url.split("/")[2]
    # print(f"{req} Request sent to {ip}")
    if response != None:
        # print(f"{req} Response Status Code: {response.status_code}:{response.reason}")
        (
            # print(json.dumps(response.json(), indent=4))
            # if response.text
            # else print("no output")
        )
    return response
 
 
def do_json_syntax_correction(json_text):
    return (
        json_text.replace(" ", "")
        .replace("\\n", "")
        .replace('\\"', '"')
        .replace('\\"', '"')
        .replace(':"{', ":{")
        .replace('}"}}', "}]}}")
        .replace("}{", "},{")
        .replace('"response":', '"response":[')
    )
 