#!/bin/bash

if [ -z "$1" ]; then
	echo "Needs target name as a first parameter"
	echo "Usage:"
	echo " $0 <target>"
	exit 1
fi

set -eu

TARGET=$1

#
# Add ARM_GCC to our path, if not already there
#
if ! arm-none-eabi-objcopy --version 2>/dev/null 1>/dev/null; then
	GCC_PATH_CONFIG=$(mbed config GCC_ARM_PATH 2>/dev/null | awk '/\/bin/{print $2;}')
	GCC_PATH="${GCC_PATH_CONFIG:-${MBED_GCC_ARM_PATH}}"
	if [ -z "$GCC_PATH" ]; then
		echo "ERROR: arm-none-eabi-objcopy not in PATH, not in MBED_GCC_ARM_PATH and GCC_ARM_PATH not set for mbed config"
		exit 1
	fi
	export PATH="$PATH:$GCC_PATH"
fi

#
# Extract settings from configs.md
#
eval $(cat configs.md | awk -F "|" "/\|$TARGET/{print \"BOOTLOADER_BIN=\"\$3,\"HEADER_OFFSET=\"\$4,\"APP_OFFSET=\"\$5,\"UPDATE_HEADER_OFFSET=\"\$6,\"UPDATE_APP_OFFSET=\"\$7;}")

#
# Find out whethet target uses .bin or .hex files
#
BIN_HEX="${BOOTLOADER_BIN##*.}"

#
# Print out some debug information
#
echo "TARGET=$TARGET"
echo "BOOTLOADER_BIN=$BOOTLOADER_BIN"
echo "HEADER_OFFSET=$HEADER_OFFSET"
echo "APP_OFFSET=$APP_OFFSET"
echo "UPDATE_HEADER_OFFSET=$UPDATE_HEADER_OFFSET"
echo "UPDATE_APP_OFFSET=$UPDATE_APP_OFFSET"
echo "BIN_HEX=$BIN_HEX"

if [ ! -f "$BOOTLOADER_BIN" ]; then
	echo "Needs: $BOOTLOADER_BIN"
	exit 1
fi

#
# Clean workspace
#
rm -rf *.hex *.bin

#
# Generate mbed_app.json from template
# An UUID is used to make certain the smoke binary gets flashed and update procedure is executed succesfully
#
APP_OUTPUT=`uuidgen`

sed -e "s/PREDEFINED_APP_OUTPUT/$APP_OUTPUT/" \
    -e "s/BOOTLOADER_BIN/${TARGET}_bootloader.${BIN_HEX}/" \
	-e "s/HEADER_OFFSET/$HEADER_OFFSET/" \
	-e "s/APP_OFFSET/$APP_OFFSET/" \
	< mbed_app.json.TEMPLATE \
	> mbed_app.json

sed -e "s/PREDEFINED_APP_OUTPUT/$APP_OUTPUT/" \
    < compare.log.TEMPLATE \
    > compare.log

#
# Build Hello World app
#
cp $BOOTLOADER_BIN ${TARGET}_bootloader.${BIN_HEX}
test -L mbed-os || ln -sf ../../mbed-os mbed-os
echo "ROOT=." > .mbed
mbed target $TARGET
mbed toolchain GCC_ARM
mbed compile

#
# Generate binary header blob
#
HEADER=./BUILD/$TARGET/GCC_ARM/smoke_header.hex
arm-none-eabi-objcopy --input-target=ihex --output-target=binary $HEADER ${HEADER/%hex/bin}
HEADER=${HEADER/%hex/bin}

#
# Convert application to binary, if required
#
APP=./BUILD/$TARGET/GCC_ARM/smoke_application.$BIN_HEX
if [ "$BIN_HEX" == "hex" ]; then
	arm-none-eabi-objcopy --input-target=ihex --output-target=binary $APP ${APP/%hex/bin}
	APP=${APP/%hex/bin}
fi

#
# Create final Flash image:
# |bootloader| slot0: empty | slot1: header + app|
#
IMG="${TARGET}_smoke.bin"

if [ "$BIN_HEX" == "hex" ]; then
	arm-none-eabi-objcopy --input-target=ihex --output-target=binary $BOOTLOADER_BIN ${IMG}
else
	cp $BOOTLOADER_BIN $IMG
fi

dd if=$HEADER of=$IMG bs=1 seek=$(($UPDATE_HEADER_OFFSET))
dd if=$APP of=$IMG bs=1 seek=$(($UPDATE_APP_OFFSET))

#
# Convert resulting binary image to hex file
# if target uses .hex
#
if [ "$BIN_HEX" == "hex" ]; then
	arm-none-eabi-objcopy --input-target=binary --output-target=ihex $IMG ${IMG/%bin/hex}
fi
