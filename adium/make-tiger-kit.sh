#!/bin/sh
# Makes purple-hotline-tiger.zip: everything build-tiger.sh needs on a Tiger Mac
# (this source, and the headers it builds against from Adium 1.3.10's source).
#   ADIUM13_SRC  unpacked adium-1.3.10.tgz (https://adiumx.cachefly.net/adium-1.3.10.tgz)
set -e
cd "$(dirname "$0")/.."
ADIUM13_SRC=${ADIUM13_SRC:-/Volumes/AppStorage/adium-dev/src-1.3.10/adium-1.3.10}
KIT=build/purple-hotline-tiger
rm -rf "$KIT" && mkdir -p "$KIT/headers/Adium" "$KIT/src" "$KIT/adium/Resources"
cp src/*.c src/*.h "$KIT/src/"
cp adium/*.h adium/*.m adium/Info.plist adium/PurpleDefaultsHotline.plist "$KIT/adium/"
cp adium/Resources/*.png "$KIT/adium/Resources/"
cp adium/build-tiger.sh adium/README-TIGER.txt LICENSE "$KIT/"
# Adium's headers (GPL, from its source), laid out as the #imports expect them
cp "$ADIUM13_SRC/Source/"*.h "$ADIUM13_SRC/Frameworks/Adium Framework/Source/"*.h "$KIT/headers/Adium/"
mkdir -p "$KIT/headers/AIUtilities" "$KIT/headers/AdiumLibpurple"
cp "$ADIUM13_SRC/Frameworks/AIUtilities Framework/Source/"*.h "$KIT/headers/AIUtilities/"
cp "$ADIUM13_SRC/Plugins/Purple Service/"*.h "$KIT/headers/AdiumLibpurple/"
cp -RL "$ADIUM13_SRC/Frameworks/libpurple.framework/Versions/0.5.9/Headers" "$KIT/headers/libpurple"
cp -RL "$ADIUM13_SRC/Frameworks/libglib.framework/Headers" "$KIT/headers/glib"
(cd build && rm -f purple-hotline-tiger.zip && zip -qry purple-hotline-tiger.zip purple-hotline-tiger)
ls -la build/purple-hotline-tiger.zip
