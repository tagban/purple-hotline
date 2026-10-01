# purple-hotline

**Hotline Instant Messaging for Adium and Pidgin.** A libpurple plugin that signs on to
Hotline messaging servers like [VesperNet](https://agora.vespernet.net/messenger), the way
[HIM](https://github.com/tagban/him) does: your Buddy List, instant messages, away messages
and Buddy Icons, plus the public chat rooms of Hotline servers around the world.

- **Secure sign-in.** HOPE with HMAC-SHA256, and the whole session encrypted with
  ChaCha20-Poly1305 when the server offers it (VesperNet does). The cryptography is built
  in, so it needs no outside library, even on old Macs.
- **Buddies.** Buddy List with presence (Available, Away, Busy, Invisible) and away
  messages, buddy requests both ways, Block, private aliases, profiles, Buddy Icons.
- **Messages.** Typing notices; messages to buddies who are away are held by the server and
  arrive when they're back.
- **Find a Buddy.** Search VesperNet by name or screen name, then add from the results.
- **Getting started.** On VesperNet the first sign-on offers to add John (who made HIM) and
  SmarterChild (a chatbot), says where Find a Buddy and the chat rooms are, and there's a
  **Get a Screen Name** link (Hotline has no sign-up command; VesperNet signs you up on
  the web).
- **Chat rooms.** Join any Hotline server's public chat. The list comes from
  [tracker.bigredh.com](https://tracker.bigredh.com) (updated hourly): busy servers first,
  with the quiet ones and the file mirrors and welcome servers a click away. Bookmark rooms
  you like. Double-click someone in a room to send them a Hotline private message.

## Adium

For Adium 1.5.10 (Intel Macs, and Apple Silicon through Rosetta).

1. Download `Hotline.AdiumLibpurplePlugin` from the
   [releases](https://github.com/tagban/purple-hotline/releases) and double-click it.
   Adium installs it and asks to restart.
2. **File > Add Account > Hotline (HIM)**. Enter your screen name and password. No screen
   name yet? **Get a Screen Name...** is right there.
3. Find people with **File > your account > Find a Buddy...**, and chat rooms with
   **File > Join Group Chat...**

A build for Adium 1.3 on Mac OS X 10.4 Tiger (PowerPC and Intel) is in the works.

## Pidgin

For Pidgin 2.14 (and Finch).

- **Windows:** download `purple-hotline-windows.zip` from the
  [releases](https://github.com/tagban/purple-hotline/releases). Put `plugins\libhotline.dll`
  in `%APPDATA%\.purple\plugins\`, and copy the `pixmaps` folder into Pidgin's folder
  (usually `C:\Program Files (x86)\Pidgin\`) for the Hotline icon. Restart Pidgin.
- **Linux:** build it (below) and `sudo make install`, or `make install-user` for just you.

Then **Accounts > Manage Accounts > Add**, protocol **Hotline**. The server is VesperNet
unless you change it under Advanced. Find a Buddy is in **Accounts > (your account)**, and
chat rooms in **Tools > Room List** or **Buddies > Join a Chat**.

## Building

Linux and macOS (with libpurple's development files, e.g. `libpurple-dev`):

```sh
make
make check        # crypto vectors, tracker data, and live sessions against HIM's mock server
sudo make install
```

`make check`'s session test needs HIM's mock server
(`cargo build -p hotline-im --features mock-server --bin mock-server` in the
[HIM](https://github.com/tagban/him) repository, next to this one, or `MOCK=` its path).

Windows: `make -f Makefile.mingw` with MinGW-w64; see the file, and
`.github/workflows/build.yml`, which builds it on every push.

Adium: `adium/build.sh`, with Adium's source and Adium.app 1.5.10 (see the script).

## The protocol

fogWraith's Hotline messaging extension and HOPE
([github.com/fogWraith/Hotline](https://github.com/fogWraith/Hotline)), as HIM speaks it.
Chat rooms are classic Hotline public chat, each on its own guest connection.

## License

MIT (see [LICENSE](LICENSE)). The Hotline "H" is redrawn from the one on
[bigredh.com](https://bigredh.com).
