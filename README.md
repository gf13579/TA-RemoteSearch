# TA-RemoteSearch

## Release history

| Date       | Version | Notes           |
| :--------- | :------ | :-------------- |
| 2022-02-15 | 0.0.1   | Initial release |
| 2022-05-27 | 0.0.2   | Various fixes |
| 2024-05-03 | 0.0.3   | Added win32_setctime.py - loguru dependency on Windows |

## Overview

This command uses the Splunk REST API to create a search job on a remote search head, retrieves the results and outputs them on the pipeline.

### Syntax

```
remotesearch base_url=<string> search=<str> include_metadata=<bool> check_cert=<bool> max_search_time=<int>
```

## Example

```
| remotesearch base_url="https://acmecorp.splunkcloud.com:8089" search="index=_internal earliest=-4h latest=now"
```

## Features

* Returns events as they would normally appear in Splunk, but with `include_metadata=True` you'll get all fields - including internal ones - returned as json
* Supports username+password or Splunk auth tokens for authentication, managed using a setup page
* Supports an explicit proxy parameter (or env variables HTTP_PROXY/HTTPS_PROXY if set - untested)

## Known limitations

* Using a transforming command like stats will require you to pipe the custom search command's output to `table` to display nicely
* Exporting a large result set can require a **signficant*** amount of memory e.g. 1GB for 500k events from _internal in verbose mode
* Search messages aren't returned when Export is used to return results in json format
* There's currently nothing logged to say that a remote job was auto-finalized due to the auto_cancel timeout, set by default to 3600s (1hr) as remotesearch's max_search_time
* No progress reported during result retrieval - once the remote search is completed you'll see the job progress go from 0% to 100%
* Passing verify=True to splunklib.connect seems to have no effect
* Testing has been limited

## Credits

* James Hodgkinson - for his [fork] (https://github.com/splunk/splunk-sdk-python/pull/435) of the Splunk Python SDK
* Marcus Schiesser - for his [neat handling] (https://marcusschiesser.de/2022/02/10/splunk-use-either-username-or-token-authentication/) of username+pw or auth tokens: 

## Source

Feel free to contribute via https://github.com/gf13579/TA-RemoteSearch