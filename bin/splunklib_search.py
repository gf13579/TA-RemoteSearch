#!/usr/bin/env python

import sys
import argparse
import os
import logging
import json
import splunklib.client as splunk_client
from urllib.parse import urlparse
import urllib

# From James Hodgkinson's fork of the Splunk Python SDK, Feb 2022
# https://github.com/splunk/splunk-sdk-python/pull/435
from splunklib.results import JSONResultsReader, Message

# For proxy support
import urllib.request
from io import BytesIO
import ssl


class splunklib_search:
    def __init__(
        self,
        base_url,
        username,
        password,
        auth_token,
        proxy=None,
        search_timeout=3600,
        check_cert=False,
        logger_name=None,
        log_level=logging.INFO,
    ):
        self._base_url = base_url
        self._session_key = None
        self._verify = check_cert
        self._search_timeout = search_timeout

        if not self._base_url.endswith("/"):
            self._base_url += "/"

        self._server = urlparse(base_url).hostname
        self._port = urlparse(base_url).port

        self._proxy = None
        if "HTTP_PROXY" in os.environ:
            self._proxy = os.environ.get("HTTP_PROXY")
        if "HTTPS_PROXY" in os.environ:
            self._proxy = os.environ.get("HTTPS_PROXY")
        if proxy:
            self._proxy = proxy

        if logger_name:
            try:
                self._logger = logging.getLogger(logger_name)
            except Exception as e:
                logging.basicConfig(format="%(created)s %(message)s")
                self._logger = logging.getLogger()
                self._logger.setLevel(log_level)
        else:
            logging.basicConfig(
                format="%(asctime)s, Level=%(levelname)s, Pid=%(process)s, Logger=%(name)s, File=%(filename)s, Line=%(lineno)s, %(message)s"
            )

            self._logger = logging.getLogger()
            self._logger.setLevel(log_level)

        self._authenticate(username=username, password=password, auth_token=auth_token)

    def handler(self, proxy):
        proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
        # return a pointer to our custom request function - which potentially has nothing to do with what we just did
        return self._request

    def _request(self, url, message, **kwargs):
        method = message["method"].lower()
        data = message.get("body", "") if method == "post" else None
        headers = dict(message.get("headers", []))
        req = urllib.request.Request(url, data, headers)

        # Added as I think the ProxyHandler code above is doing nothing right now
        req.set_proxy(self._proxy, "https")

        # To Splunk app vetting team - support for *not* verifying certs is here because Splunk's default is to use self-signed
        # and neither Splunk Enterprise nor Splunk Cloud provide UI options/guidance to address this, meaning customers rarely do
        # Please do not fail this app for providing the option to not validate certs
        if self._verify:
            try:
                response = urllib.request.urlopen(req)
            except urllib.error.HTTPError as response:
                pass  # Propagate HTTP errors via the returned response message
        else:
            try:
                response = urllib.request.urlopen(
                    req, context=ssl._create_unverified_context()
                )
            except urllib.error.HTTPError as response:
                pass  # Propagate HTTP errors via the returned response message
        return {
            "status": response.code,
            "reason": response.msg,
            "headers": dict(response.info()),
            "body": BytesIO(response.read()),
        }

    def _connect(self, **kwargs):
        """
        _connect makes a connection to Splunk, handling username+password OR auth token

        :return: the results of calling splunk_client.connect i.e service object
        """

        # remove `None` parameters (otherwise splunklib.client.connect will fail)
        for key in ["username", "password", "token", "host", "port"]:
            if key in kwargs and kwargs[key] is None:
                del kwargs[key]

        kwargs["autoLogin"] = True

        # ensure parameters
        for key in ["host", "port"]:
            if key not in kwargs:
                raise ValueError(f"Can't connect to Splunk. Missing {key} parameter")
        if "username" in kwargs and "password" not in kwargs:
            raise ValueError(
                f"Can't connect to Splunk {kwargs['host']}. Missing password for username authentication"
            )
        if "username" not in kwargs and "token" not in kwargs:
            raise ValueError(
                f"Can't connect to Splunk {kwargs['host']}. Either token or username must be set for authentication"
            )

        if self._proxy:
            return splunk_client.connect(handler=self.handler(self._proxy), **kwargs)
            # This also works: `return splunk_client.connect(handler=self._request, **kwargs)`, probably as I'm not using ProxyHandler properly
        else:
            return splunk_client.connect(**kwargs)

    def _authenticate(self, username, password, auth_token):
        try:
            self._service = self._connect(
                username=username,
                password=password,
                token=auth_token,
                host=self._server,
                port=self._port,
                verify=self._verify,
            )
        except Exception as e:
            error_string = f"Failed to authenticate against {self._base_url} with provided credentials. Exception: {e}"
            self._logger.log(logging.ERROR, error_string)
            raise Exception(error_string)

    def run_search(self, search, max_search_time=3600):
        """
        From https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs

            auto_cancel	0	If specified, the job automatically cancels after this many seconds of inactivity. (0 means never auto-cancel)
            max_time	0	The number of seconds to run this search before finalizing. Specify 0 to never finalize.
            timeout	Number	86400	The number of seconds to keep this search after processing has stopped.
        """

        # Prepend 'search' unless we already have a '| [command]'
        search = search.strip()
        if not (search.startswith("|") or search.startswith("search ")):
            search = "search " + search

        # Use '| table *' to ensure we retrieve all fields rather than just _raw
        # Store _time as _epochtime to restore as _time later on

        search += " | eval _epochtime = _time | table *"

        kwargs_search = {
            "output_mode": "json",
            "adhoc_search_level": "verbose",
            "count": 0,
            "max_time": max_search_time,
        }

        runner = getattr(self._service.jobs, "export")

        # I'm not sure there's actually any value in trying to use yield here over collecting the results in a list and returning them
        # I'm also tempted to run self._service.jobs.export on its own, before then iterating over the results
        # as we're getting them all at once anyway, and it'd mean we could log more meaningful events about what's happening

        # results = []
        self._logger.log(logging.INFO, f"About to initiate remote search")
        for result in JSONResultsReader(runner(search, **kwargs_search)):
            if isinstance(result, Message):
                message = "message: ", json.dumps(result, indent=4, default=str)
                self._logger.log(logging.INFO, message)

            if "result" in result:
                if "_epochtime" in result["result"]:
                    result["result"]["_time"] = result["result"]["_epochtime"]
                # results.append(result['result'])
                yield result["result"]
            else:
                self._logger.log(logging.ERROR, f"No 'result' key in result: {result}")

        # message=f"Number of results retrieved: {len(results)}"
        # self._logger.log(logging.INFO, message)

        # return results


#################################################


def main() -> int:
    """
    main is just use for testing the module independently of splunk

    :return: success (zero) or failure (non-zero)
    """
    parser = argparse.ArgumentParser(description="Query Splunk via API")

    parser.add_argument("--base_url", nargs=1, required=True)
    parser.add_argument("--search", nargs=1, required=True)
    parser.add_argument("--check_cert", nargs=1, required=False, default=False)
    args = parser.parse_args()

    base_url = args.base_url[0]
    search = args.search[0]

    if "SPL_USERNAME" in os.environ and "SPL_PASSWORD" in os.environ:
        username = os.environ["SPL_USERNAME"]
        password = os.environ["SPL_PASSWORD"]
        auth_token = None
    elif "SPL_AUTH_TOKEN" in os.environ:
        auth_token = os.environ["SPL_AUTH_TOKEN"]
        username = password = None
    else:
        logging.error(
            "Store Splunk username and password in env vars for testing: SPL_USERNAME and SPL_PASSWORD"
        )
        logging.error("e.g. export SPL_USERNAME=admin SPL_PASSWORD=your_password_here")
        return 1

    proxy = None
    api_search = splunklib_search(
        base_url=base_url,
        username=username,
        password=password,
        auth_token=auth_token,
        proxy=proxy,
    )

    results = api_search.run_search(search=search)
    return 0


if __name__ == "__main__":
    sys.exit(main())
