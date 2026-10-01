#!/bin/sh
# Builds Hotline.AdiumLibpurplePlugin for Adium 1.3 on Mac OS X 10.4 Tiger, PowerPC
# and Intel in one bundle. Run it on the Tiger Mac, with Xcode 2.5 installed, from
# the unzipped kit (make-tiger-kit.sh makes it):
#
#   cd purple-hotline-tiger && sh build-tiger.sh
#
# ADIUM_APP is Adium 1.3.x (default /Applications/Adium.app). Everything it says goes
# to build.log too: send that file along if something goes wrong.
ADIUM_APP=${ADIUM_APP:-/Applications/Adium.app}
SDK=${SDK:-/Developer/SDKs/MacOSX10.4u.sdk}
CC=${CC:-gcc-4.0}
ARCHS=${ARCHS:-"-arch ppc -arch i386"}
OUT=build/Hotline.AdiumLibpurplePlugin
FW="$ADIUM_APP/Contents/Frameworks"

cd "`dirname "$0"`"

build() {
echo "purple-hotline Tiger build, `date`"
sw_vers
$CC --version | head -1

fail() { echo "FAILED: $1"; echo; echo "(build.log has the details)"; exit 1; }
[ -d "$SDK" ] || fail "no 10.4 SDK at $SDK: install Xcode 2.5 (with the 10.4 Universal SDK)"
[ -d "$FW/libpurple.framework" ] || fail "no Adium at $ADIUM_APP: install Adium 1.3.10 there, or set ADIUM_APP"

rm -rf build && mkdir -p build/obj "$OUT/Contents/MacOS" "$OUT/Contents/Resources"
COMMON="$ARCHS -isysroot $SDK -mmacosx-version-min=10.4 -O2 -g -Iheaders -Iheaders/libpurple -Iheaders/glib -Isrc -DPURPLE_STATIC_PRPL -DHL_ADIUM_13"

for c in src/hotline.c src/hl_wire.c src/hl_crypto.c src/hl_json.c src/hl_tracker.c src/hl_room.c; do
	echo "== $c"
	$CC $COMMON -std=gnu99 -Wall -Wno-unused-parameter -c "$c" -o "build/obj/`basename $c .c`.o" || fail "$c"
done
for m in adium/HotlinePlugin.m adium/HotlineService.m adium/HotlineAccount.m adium/HotlineAccountViewController.m adium/HotlineJoinChatViewController.m; do
	echo "== $m"
	$CC $COMMON -include Cocoa/Cocoa.h -c "$m" -o "build/obj/`basename $m .m`.o" || fail "$m"
done

# Adium 1.3 keeps the libpurple classes (CBPurpleAccount, PurpleService) in its
# Purple.AdiumPlugin bundle, not a framework: they're found when Adium loads us.
echo "== link"
$CC $ARCHS -isysroot $SDK -mmacosx-version-min=10.4 -bundle -undefined dynamic_lookup \
	-o "$OUT/Contents/MacOS/Hotline" build/obj/*.o \
	-F"$FW" -framework Adium -framework AIUtilities -framework libpurple -framework libglib \
	-framework Cocoa || fail "link"

sed 's|<string>1.5</string>|<string>1.3</string>|' adium/Info.plist > "$OUT/Contents/Info.plist"
cp adium/PurpleDefaultsHotline.plist adium/Resources/*.png "$OUT/Contents/Resources/"
file "$OUT/Contents/MacOS/Hotline"
echo
echo "Built $OUT"
echo "Double-click it (Adium installs it), or copy it into"
echo "~/Library/Application Support/Adium 2.0/PlugIns/ and restart Adium."
}

# Shown as it goes, and kept in build.log.
build 2>&1 | tee build.log
