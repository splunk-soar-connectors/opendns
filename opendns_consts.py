# File: opendns_consts.py
#
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
OPENDNS_JSON_DOMAIN = "domain"
OPENDNS_JSON_IP = "ip"
OPENDNS_JSON_APIKEY = "apikey"
OPENDNS_JSON_STATUS_DESC = "status_desc"
OPENDNS_JSON_DOMAIN_STATUS = "domain_status"
OPENDNS_JSON_IP_STATUS = "ip_status"
OPENDNS_JSON_TOTAL_BLOCKED_DOMAINS = "total_blocked_domains"
OPENDNS_REG_ORG = "organization"
OPENDNS_REG_CITY = "city"
OPENDNS_REG_COUNTRY = "country"
OPENDNS_JSON_CATEGORIES = "category"
OPENDNS_JSON_CATEGORY_INFO = "category_info"
OPENDNS_JSON_CO_OCCUR = "co_occurances"
OPENDNS_JSON_RELATIVE_LINKS = "relative_links"
OPENDNS_JSON_TOTAL_OCO_OCCUR = "total_co_occurances"
OPENDNS_JSON_TOTAL_RELATIVE_LINKS = "total_relative_links"
OPENDNS_JSON_SECURITY_INFO = "security_info"
OPENDNS_JSON_TAG_INFO = "tag_info"
OPENDNS_JSON_TOTAL_TAG_INFO = "total_tag_info"
OPENDNS_JSON_FEATURES = "features"
OPENDNS_JSON_RISK_SCORE = "riskScore"

OPENDNS_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"
OPENDNS_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
OPENDNS_ERR_SERVER_CONNECTION = "Connection failed"
OPENDNS_ERR_FROM_SERVER = "API failed, Status code: {status}, Message from server: {message}"
OPENDNS_MSG_GET_DOMAIN_TEST = "Querying a single domain to check credentials"

OPENDNS_USING_BASE_URL = "Using url: {base_url}"

OPENDNS_REST_API_URL = "https://investigate.api.opendns.com"
STATUS_DESC = {
        '0': 'NO STATUS',
        '1': 'NON MALICIOUS',
        '-1': 'MALICIOUS'}
