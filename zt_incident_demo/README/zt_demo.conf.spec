[hec]
url = <string>
* HTTP Event Collector base URL, for example https://http-inputs-mystack.splunkcloud.com:443
verify_tls = <boolean>
token_name = <string>
* Name of the HEC token whose value is read through REST at runtime (never stored on disk).

[emulator]
url = <string>
* Base URL of the Kubernetes API emulator.
verify_tls = <boolean>

[stream]
day_shape_tz = <string>
* Time zone used to shape the daily background (busier between 08:00 and 20:00 local).
backfill_hours = <integer>
chunk_minutes = <integer>

[modes]
speed = fast|normal
response_mode = local|soar
agent_mode = mcp|inline
