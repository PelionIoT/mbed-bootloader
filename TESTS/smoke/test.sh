#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
	echo "Needs target and RAAS parameters"
	echo "Usage:"
	echo " $0 <target> <raas>"
	exit 1
fi

set -eu

TARGET=$1
RAAS=$2

#
# Extract settings from configs.md
#
eval $(cat configs.md | awk -F "|" "/\|$TARGET/{print \"BOOTLOADER_BIN=\"\$3,\"HEADER_OFFSET=\"\$4,\"APP_OFFSET=\"\$5,\"UPDATE_HEADER_OFFSET=\"\$6,\"UPDATE_APP_OFFSET=\"\$7;}")

#
# Find out whethet target uses .bin or .hex files
#
BIN_HEX="${BOOTLOADER_BIN##*.}"
IMG="${TARGET}_smoke.${BIN_HEX}"

if [ ! -f "$IMG" ]; then
	echo "Needs $IMG"
	exit 1
fi

#
# Run the binary in the RAAS and compare the serial output
# to compare.log file's content
#
mbedhtrun -m $TARGET -p DUMMY:115200 -f "$IMG" --grm raas_client:$RAAS -C 0 -P 240 -v --compare-log=compare.log -R 0
