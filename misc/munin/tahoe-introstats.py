#! /usr/bin/python

import os, sys
import urllib
import simplejson

configinfo = """\
graph_title Tahoe Introducer Stats
graph_vlabel hosts
graph_info This graph shows the number of hosts announcing and subscribing to various services
storage_server.label Storage Servers
storage_server.draw LINE1
storage_client.label Clients
storage_client.draw LINE2
"""

if len(sys.argv) > 1:
    if sys.argv[1] == "config":
        print configinfo.rstrip()
        sys.exit(0)

url = os.environ["url"]

data = simplejson.loads(urllib.urlopen(url).read())
print "storage_server.value %d" % data["announcement_summary"]["storage"]
print "storage_client.value %d" % data["subscription_summary"]["storage"]
