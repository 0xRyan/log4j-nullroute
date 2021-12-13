# log4j-nullroute
Quick script to ingest IP feed from greynoise.io for log4j (CVE-2021-44228) and null route bad addresses. Works w/Cisco and Arista.

Use the exceptions file to omit any IPs you find in the list that you do not want to null route.

Required fill-ins for vars:

secrets.py
------------
username, password, api_key

nullroute.py
-------------
edge_routers