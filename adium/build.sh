#!/bin/sh
# Builds Hotline.AdiumLibpurplePlugin for Adium 1.5.10 (Intel 64-bit; Apple Silicon
# Macs run it under Rosetta, as they run Adium).
#
#   ADIUM_SRC  Adium's source (git clone https://github.com/adium/adium): headers
#   ADIUM_APP  Adium.app 1.5.10.x: the frameworks the plugin links against
#
# Glib's headers come from pkg-config (any 2.x); the version macros below keep the
# plugin to what Adium's own glib (2.42) has.
set -e
cd "$(dirname "$0")"
ADIUM_SRC=${ADIUM_SRC:-/Volumes/AppStorage/adium-dev/adium-src}
ADIUM_APP=${ADIUM_APP:-/Volumes/AppStorage/adium-dev/Adium.app}
OUT=build/Hotline.AdiumLibpurplePlugin
INC=build/include

for d in "$ADIUM_SRC/Frameworks/Adium/Source" "$ADIUM_APP/Contents/Frameworks/AdiumLibpurple.framework"; do
	[ -e "$d" ] || { echo "missing $d (set ADIUM_SRC / ADIUM_APP)" >&2; exit 2; }
done

# Adium's headers are imported as <Adium/...>, <AIUtilities/...>, <AdiumLibpurple/...>, <libpurple/...>.
rm -rf build && mkdir -p "$INC" "$OUT/Contents/MacOS" "$OUT/Contents/Resources" build/obj
# <Adium/...> is the framework's headers plus some of the app's own.
mkdir -p "$INC/Adium"
for h in "$ADIUM_SRC/Source/"*.h "$ADIUM_SRC/Frameworks/Adium/Source/"*.h; do
	ln -sf "$h" "$INC/Adium/$(basename "$h")"
done
ln -s "$ADIUM_SRC/Frameworks/AIUtilities/Source" "$INC/AIUtilities"
ln -s "$ADIUM_SRC/Plugins/Purple Service" "$INC/AdiumLibpurple"
ln -s "$ADIUM_SRC/Frameworks/libpurple.framework/Headers" "$INC/libpurple"

ARCH="-arch x86_64 -mmacosx-version-min=10.9"
GLIB="$(pkg-config --cflags glib-2.0) -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_40 -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_40"
COMMON="$ARCH -O2 -g -I$INC -I$INC/libpurple -I../src $GLIB -DPURPLE_STATIC_PRPL -DHAVE_CONFIG_H=0"
WARN="-Wall -Wno-#pragma-messages -Wno-unused-parameter -Wno-deprecated-declarations -Wno-missing-field-initializers"

for c in ../src/hotline.c ../src/hl_wire.c ../src/hl_crypto.c; do
	cc $COMMON $WARN -c "$c" -o "build/obj/$(basename "$c" .c).o"
done
for m in HotlinePlugin.m HotlineService.m HotlineAccount.m HotlineAccountViewController.m; do
	cc $COMMON -fno-objc-arc -include Cocoa/Cocoa.h -Wno-everything -c "$m" -o "build/obj/$(basename "$m" .m).o"
done

FW="$ADIUM_APP/Contents/Frameworks"
cc $ARCH -bundle -o "$OUT/Contents/MacOS/Hotline" build/obj/*.o \
	-F"$FW" -framework Adium -framework AdiumLibpurple -framework AIUtilities \
	-framework libpurple -framework libglib -framework Cocoa

cp Info.plist "$OUT/Contents/"
cp PurpleDefaultsHotline.plist Resources/*.png "$OUT/Contents/Resources/"
codesign --force --sign "${SIGN:--}" "$OUT" >/dev/null 2>&1 || true
echo "built $OUT"
