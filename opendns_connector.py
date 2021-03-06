# File: opendns_connector.py
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
#
#
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from opendns_consts import *

import requests
import simplejson as json


class OpendnsConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_LOOKUP_IP = "lookup_ip"
    ACTION_ID_LOOKUP_DOMAIN = "lookup_domain"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"

    def __init__(self):

        # Call the BaseConnectors init first
        super(OpendnsConnector, self).__init__()

    def initialize(self):

        # Base URL
        self._base_url = OPENDNS_REST_API_URL
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        self._host = self._base_url[self._base_url.find('//') + 2:]

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, request_params, action_result):

        config = self.get_config()

        # username = 'Bearer ' + config[OPENDNS_JSON_APIKEY]
        # password = None

        headers = {'Authorization': 'Bearer {0}'.format(config[OPENDNS_JSON_APIKEY])}

        resp_json = None
        status_code = None

        try:
            r = requests.get(self._base_url + endpoint, headers=headers, params=request_params)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, OPENDNS_ERR_SERVER_CONNECTION, e), resp_json, status_code)

        # self.debug_print('REST url: {0}'.format(r.url))
        try:
            if (r.text.lower() == 'no data'):
                return (action_result.set_status(phantom.APP_ERROR, "OpenDNS returned no data"), resp_json, status_code)

            resp_json = r.json()
            status_code = r.status_code
        except Exception as e:
            self.debug_print("Unable to parse response", e)
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response"), resp_json, status_code)

        if (r.status_code == 204):  # success, but no data
            return (phantom.APP_SUCCESS, resp_json, status_code)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (action_result.set_status(phantom.APP_ERROR, OPENDNS_ERR_FROM_SERVER, status=r.status_code,
                message=resp_json.get('error', resp_json.get('errorMessage', 'N/A'))), resp_json, status_code)

        return (phantom.APP_SUCCESS, resp_json, status_code)

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(OPENDNS_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        endpoint = '/domains/categorization/phantomcyber.com'

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(OPENDNS_MSG_GET_DOMAIN_TEST)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())
            self.save_progress(OPENDNS_ERR_CONNECTIVITY_TEST)
            return action_result.get_status()

        self.save_progress(OPENDNS_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_domain_category_info(self, domain, data, summary, action_result):

        endpoint = '/domains/categorization/{0}?showLabels'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # parse the category response
        domain_cat_info = response.get(domain)
        if (not domain_cat_info):
            return action_result.set_status(phantom.APP_ERROR, "Queried domain not found in response")

        try:
            status_desc = STATUS_DESC.get(str(domain_cat_info.get('status', 0)), 'UNKNOWN')
        except:
            status_desc = "UNKNOWN"

        try:
            categories = ', '.join(domain_cat_info.get('content_categories', '') + domain_cat_info.get('security_categories', ''))
        except:
            categories = ''

        data[OPENDNS_JSON_STATUS_DESC] = status_desc
        data[OPENDNS_JSON_CATEGORIES] = categories
        data[OPENDNS_JSON_CATEGORY_INFO] = domain_cat_info
        summary.update({OPENDNS_JSON_DOMAIN_STATUS: status_desc})

        return phantom.APP_SUCCESS

    def _add_domain_relation_info(self, domain, data, summary, action_result):

        endpoint = '/links/name/{0}.json'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # parse the response
        links = response.get('tb1')
        if (links):
            data[OPENDNS_JSON_RELATIVE_LINKS] = links
            summary.update({OPENDNS_JSON_TOTAL_RELATIVE_LINKS: len(links)})
        else:
            summary.update({OPENDNS_JSON_TOTAL_RELATIVE_LINKS: 0})

        return phantom.APP_SUCCESS

    def _add_domain_recommendation_info(self, domain, data, summary, action_result):

        endpoint = '/recommendations/name/{0}.json'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # parse the response
        co_occurances = response.get('pfs2')
        if (co_occurances):
            data[OPENDNS_JSON_CO_OCCUR] = co_occurances
            summary.update({OPENDNS_JSON_TOTAL_OCO_OCCUR: len(co_occurances)})
        else:
            summary.update({OPENDNS_JSON_TOTAL_OCO_OCCUR: 0})

        return phantom.APP_SUCCESS

    def _add_domain_security_info(self, domain, data, summary, action_result):

        endpoint = '/security/name/{0}.json'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # parse the response
        if (status_code != 204):
            data[OPENDNS_JSON_SECURITY_INFO] = response

        return phantom.APP_SUCCESS

    def _add_domain_tagging_info(self, domain, data, summary, action_result):

        endpoint = '/timeline/{0}'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

        # parse the response
        if (response):
            data[OPENDNS_JSON_TAG_INFO] = response
            summary.update({OPENDNS_JSON_TOTAL_TAG_INFO: len(response)})
        else:
            summary.update({OPENDNS_JSON_TOTAL_TAG_INFO: 0})

        return phantom.APP_SUCCESS

    def _add_domain_risk_score_info(self, domain, data, summary, action_result):
        endpoint = '/domains/risk-score/{0}'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

        # parse the response
        if (response):
            data[OPENDNS_JSON_FEATURES] = response.get(OPENDNS_JSON_FEATURES, [])
            risk_score = response.get(OPENDNS_JSON_RISK_SCORE, 0)
            data[OPENDNS_JSON_RISK_SCORE] = risk_score
            summary.update({OPENDNS_JSON_RISK_SCORE: risk_score})

        return phantom.APP_SUCCESS

    def _lookup_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Progress
        self.save_progress(OPENDNS_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        domain = param[OPENDNS_JSON_DOMAIN]

        # Add the data that will include info about this domain
        data = action_result.add_data({})
        summary = action_result.update_summary({})

        # Category info
        ret_val = self._get_domain_category_info(domain, data, summary, action_result)

        if (not ret_val):
            return action_result.get_status()

        # Recommendations info
        ret_val = self._add_domain_recommendation_info(domain, data, summary, action_result)

        if (not ret_val):
            return action_result.get_status()

        # Relation info
        ret_val = self._add_domain_relation_info(domain, data, summary, action_result)

        if (not ret_val):
            return action_result.get_status()

        # Security info
        ret_val = self._add_domain_security_info(domain, data, summary, action_result)

        if (not ret_val):
            return action_result.get_status()

        # Domain Tagging info
        ret_val = self._add_domain_tagging_info(domain, data, summary, action_result)

        if (not ret_val):
            return action_result.get_status()

        # risk score
        ret_val = self._add_domain_risk_score_info(domain, data, summary, action_result)

        if (not ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Progress
        self.save_progress(OPENDNS_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        ip = param[OPENDNS_JSON_IP]

        endpoint = '/ips/{0}/latest_domains'.format(ip)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

        # parse the response
        if (status_code == 204):
            status_desc = STATUS_DESC['0']  # UNKNOWN

        if (not response):
            return action_result.set_status(phantom.APP_ERROR, "Response does not contain any data")

        try:
            block_domains = len(response)
            if (block_domains == 0):
                status_desc = STATUS_DESC['1']  # SAFE
            else:
                status_desc = STATUS_DESC['-1']  # MALICIOUS

            for blocked_domain in response:
                action_result.add_data(blocked_domain)
        except Exception as e:
            self.debug_print("Unable to parse response from the server", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response from the server")

        action_result.update_summary({OPENDNS_JSON_IP_STATUS: status_desc, OPENDNS_JSON_TOTAL_BLOCKED_DOMAINS: block_domains})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _whois_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Progress
        self.save_progress(OPENDNS_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        domain = param[OPENDNS_JSON_DOMAIN]

        # Assume that it is a url
        hostname = phantom.get_host_from_url(domain)
        # If it is a URL then the hostname will get extracted else use the domain as is
        if (hostname):
            domain = hostname

        slash_pos = domain.find('/')

        if (slash_pos != -1):
            domain = domain[:slash_pos]

        endpoint = '/whois/{0}'.format(domain)

        ret_val, response, status_code = self._make_rest_call(endpoint, None, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

        action_result.add_data(response)

        summary = action_result.update_summary({})

        summary[OPENDNS_REG_ORG] = response.get('registrantOrganization', '')
        summary[OPENDNS_REG_CITY] = response.get('registrantCity', '')
        summary[OPENDNS_REG_COUNTRY] = response.get('registrantCountry', '')

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions

            Args:

            Return:
                A status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if (action == self.ACTION_ID_LOOKUP_IP):
            ret_val = self._lookup_ip(param)
        elif (action == self.ACTION_ID_LOOKUP_DOMAIN):
            ret_val = self._lookup_domain(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_domain(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    # import simplejson as json
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = OpendnsConnector()
        connector._handle_action(json.dumps(in_json), None)

    exit(0)
