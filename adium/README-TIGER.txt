Hotline for Adium on Mac OS X 10.4 Tiger
=========================================

This builds the Hotline plugin for Adium 1.3 on your own Tiger Mac (PowerPC G3/G4/G5
or Intel). The result works in Adium 1.3.x on any Tiger Mac, PowerPC or Intel.

You need, on the Tiger Mac:

  1. Xcode 2.5 (from Apple's developer downloads: xcode25_8m2558_developerdvd.dmg).
     Install it with the "Mac OS X 10.4 (Universal)" SDK checked (it is by default).
  2. Adium 1.3.10 in /Applications (Adium_1.3.10.dmg; drag Adium to Applications).
  3. This folder, unzipped anywhere (your Desktop is fine).

Build it:

  1. Open Terminal (Applications > Utilities > Terminal).
  2. Type  cd  and a space, drag this folder onto the Terminal window, press Return.
  3. Type  sh build-tiger.sh  and press Return. It takes a minute or two and ends
     with "Built build/Hotline.AdiumLibpurplePlugin".

Install it:

  1. Quit Adium.
  2. In the Finder, open this folder's "build" folder and double-click
     Hotline.AdiumLibpurplePlugin. Adium starts and installs it (or copy it into
     your home folder's Library/Application Support/Adium 2.0/PlugIns/).
  3. Adium may ask whether to load a third-party plugin: say yes.

Sign on:

  Adium > Preferences > Accounts, click +, choose Hotline (HIM). Enter your VesperNet
  screen name and password (no screen name? "Get a Screen Name..." opens the sign-up
  page, or get one from another computer at https://agora.vespernet.net/messenger).

  Find people: File > (your account) > Find a Buddy...
  Chat rooms:  File > Join Group Chat...

If something goes wrong, send build.log from this folder (it's written while
building), or Adium's crash report, the same way this kit arrived.
