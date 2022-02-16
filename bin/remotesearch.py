#!/usr/bin/env python

import sys
import os
import time
import json

# For the SDK
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)

# Our TA's custom module
import splunklib_search


@Configuration()
class remotesearchCommand(GeneratingCommand):
    """Runs a search on a remote search head and returns the results

    ##Syntax

    `| remotesearch base_url="https://mysplunk" search="search index=something...`

    ##Description

    Runs a search on a remote search head and returns the results

    """

    base_url = Option(require=True)
    search = Option(require=True)
    include_metadata = Option(require=False, default=False)
    max_search_time = Option(require=False)
    check_cert = Option(require=False)

    def generate(self):
        base_url = self.base_url
        search = self.search
        include_metadata = self.include_metadata or False
        max_search_time = self.max_search_time or 3600
        check_cert = self.check_cert

        username = password = auth_token = None

        storage_passwords = self.service.storage_passwords
        for k in storage_passwords:
            p = str(k.content.get("clear_password"))
            realm = str(k.content.get("realm"))
            if realm == "TA-RemoteSearch_realm":
                creds_json = json.loads(p)
                if "username" in creds_json and "password" in creds_json:
                    if creds_json["username"] != "" and creds_json["password"] != "":
                        username = creds_json["username"]
                        password = creds_json["password"]
                if "auth_token" in creds_json and creds_json["auth_token"] != "":
                    auth_token = creds_json["auth_token"]
        if (not username or not password) and not auth_token:
            error = "error retrieving  credentials - are they defined?"
            self.logger.error(error)
            yield {"_time": time.time(), "creds": error}
            return

        api_search = splunklib_search.splunklib_search(
            base_url=base_url,
            username=username,
            password=password,
            auth_token=auth_token,
            logger_name=self.logger.name,
            check_cert=check_cert,
        )
        results = api_search.run_search(search=search, max_search_time=max_search_time)

        if include_metadata:
            for result in results:
                yield {"_raw": result}
        else:
            for result in results:
                yield result


dispatch(remotesearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
