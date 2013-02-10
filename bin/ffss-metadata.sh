#!/bin/bash
#
# This is just a simple script to generate a valid metadata option.
# Use this as a template, and change it for your needs.
#
# Defaults:
ENGINE="suricata-1.4"
ORG="acme"
USER="user"
TLP="amber"
TYPE="generic"
KILLCHAIN="c2"
DATE=`date --iso`
# # # # # # # # # # # # # #
echo "metadata:author $ORG-$USER, dengine $ENGINE, tlp $TLP, type $TYPE, killchain $KILLCHAIN, intrusionset none, enabled yes, date_created $DATE, date_modified $DATE;"

