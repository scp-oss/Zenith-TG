# CLAUDE.md

Operational notes for Claude sessions working on this repo — dense, for an
agent, not prose for an external reader (that's what README.md is for).
Do not put server names, individual people's names, or unpublished/draft
project names here — same public-repo constraint as README.md (NETH-4 is
an internal codename already used throughout this engagement, not a real
hostname — same convention as z2r_autobench's own CLAUDE.md).

## Android MTProto investigation (started 2026-08-22)

**Status: mitigated via `mtproxy_relay.py`, root cause of `transparent_relay.py`'s
Android failure still UNRESOLVED.** See "Path taken" at the end of this
section for what was actually shipped. Everything below this line is the
original investigation trail, kept intact for context.

**Symptom:** `relay/transparent_relay.py` (transparent, no-secret MTProto
relay) works fine on iPhone, but Telegram never gets past "Connecting..."
on two separate Android devices on the same network/VLESS tunnel. This
section is the full trail so a future session (or a fresh one after this
one ran out of context) doesn't have to re-derive any of it.

### Ruled out, in the order investigated

1. **DHCP/DNS was not the cause.** A parallel, unrelated incident that
   day (z2r_autobench side, see that repo's own CLAUDE.md) had already
   broken and then fixed system DNS on NETH-4 — checked and ruled out as
   a factor here; this relay resolves fine.
2. **Dead CF-fallback fronting domains** (`vendor/config.py`,
   `Flowseal/tg-ws-proxy`'s published domain list) — all 20 resolved to
   `gaierror(-5, 'No address associated with hostname')` (domain exists,
   no A/AAAA record — upstream domains are just dead, not a censorship
   or DNS-provider issue). **Fixed** in commit `ada2100`: expanded
   `DEFAULT_DC_IP` in `transparent_relay.py` from `{2, 4}` to all 5 real
   DCs (`1..5`), all pointed at the same `149.154.167.220` WebSocket
   gateway — `ws_domains()` already builds a per-DC Host domain
   generically, so this was a pure config gap, not a design limitation.
   This closes the need for the fallback path entirely for any
   legitimately-decoded connection.
3. **False-positive MTProto detection.** Before the `dc_id` range check
   existed, a large stream of unrelated non-MTProto TCP traffic sharing
   Telegram's CIDR (caught by the same iptables REDIRECT) would
   occasionally have its 4-byte `proto_tag` field coincidentally match
   one of the 3 known tags after AES-CTR decode — producing absurd
   `DC16712`-style hits (Telegram DC ids are ONLY ever 1-5, or +10000 for
   test). Confirmed this was happening in volume specifically right
   after reopening Telegram on Android (dozens of hits/second). **Fixed**
   in commit `a44c1f8`: `_decode_direct_client_init()` now rejects any
   decoded `dc_id` outside `_REAL_DC_IDS = {1..5} ∪ {10001..10005}`
   before ever treating a connection as a genuine client.
4. **Happ (Android VPN client) "preferred API type" was `Auto`, iOS's
   Happ defaults to `IPv4` explicitly** — a real, confirmed client-side
   difference (found live, not guessed) that looked like a strong
   suspect (IPv6 leak bypassing the VLESS tunnel entirely — YouTube/
   Instagram working while Telegram didn't fit that pattern, since IPv6
   leak would only affect whichever specific connections resolve/route
   over IPv6 at that moment). **Set to IPv4 on Android to match iOS —
   did NOT fix the issue.** Ruled out as sole cause, though leaving it on
   IPv4 is still correct hygiene regardless.

### The actual finding (raw bytes, not a guess)

Added a temporary diagnostic (`-v`/`--verbose`, commit `14135fc`) that
logs the first 16 bytes of any handshake `_decode_direct_client_init()`
rejects. Captured live from Android reopening Telegram:

```
16030106e6010006e20303f72e066e64
160301072601000722030349e56acafc
16030106e4010006e00303688e64716d
1603010726010007220303ea291996e5
16030107240100072003035e8cebd0c3
16030106e6010006e2030365c3bff436
1603010706010007020303e93964fb8d
16030106c6010006c20303db8291ef55
```

Every single one starts `16 03 01`/`16 03 03` (TLS record: Handshake,
TLS1.0/1.2) followed by `01 00 XX XX` (Handshake type ClientHello +
length) then `03 03` again (ClientHello's own `client_version` = TLS1.2)
then `client_random`. **This is a genuine, real TLS ClientHello** — not
obfuscated2 MTProto's random-looking 64-byte prefix, which is what
`_decode_direct_client_init()` is built to parse (raw key derived
straight from the packet, no secret — see that function's docstring and
`prober/proto.py`).

All destination IPs for these connections were real Telegram DC
addresses (`149.154.167.99`, `149.154.170.200`, `149.154.174.200`,
`149.154.167.51`, `149.154.167.41`, `149.154.167.222`, `149.154.175.54`)
— and every one of them, once passed through as plain TCP passthrough
(since `_decode_direct_client_init()` correctly refuses to touch real
TLS), timed out / failed to connect.

**Correction, checked directly with a bare `curl` from NETH-4 bypassing
the relay entirely** (`curl -v --connect-timeout 4 https://<ip>:443/`
for `.51`/`.41`/`.222`/`175.54`): these are **NOT** SYN-null-routed like
`149.154.167.99`/web.telegram.org already documented in the README. TCP
connects fine, ClientHello goes out (curl logs `TLS handshake, Client
hello (1)`), then it silently times out waiting for a ServerHello — no
RST, no response. That's a DPI blackhole triggered by inspecting the
handshake itself, not an IP-level block — in principle the same class of
thing `--lua-desync=` (ClientHello fragmentation) already defeats
elsewhere in this project, unlike the earlier, different `.99` case.
Whether that's actually exploitable here (the traffic in question is
Android's own outbound, not something z2r_autobench's zapret2 currently
targets) wasn't pursued further before the pivot below — worth
revisiting if `mtproxy_relay.py` turns out not to be a full fix.

### What this means, and what's still open

- `verify_client_hello()` in `relay/vendor/fake_tls.py` (real Fake-TLS,
  the MTProxy masking transport) requires a pre-shared secret via HMAC
  over `client_random` — that's for clients with a manually-configured
  `tg://proxy?...` link. A **direct, unconfigured** client (the whole
  premise this relay is built on) has no secret to use for that, so this
  traffic is very unlikely to be classic Fake-TLS in the MTProxy sense.
- Leading hypothesis, NOT yet confirmed: recent Telegram Android builds
  may have a built-in "detect restrictive network, wrap in TLS" fallback
  transport that activates automatically (no user proxy config needed),
  separate from both plain obfuscated2 and manually-configured Fake-TLS.
  If true, decoding/relaying it would require reverse-engineering
  whatever scheme that transport actually uses — not yet attempted.
- **CONFIRMED, not just the startup burst:** checked a settled window (app
  left open ~90s, not immediately after reopening) and the *steady-state*
  traffic was still 100% TLS-shaped, zero `прямой клиент` hits, ever.
  Android does not send obfuscated2 to this relay at any point observed —
  not just during the initial multi-DC probe burst. Rules out "wait for
  the burst to settle" as an explanation.
- Still not checked: does Telegram actually send/receive messages despite
  the perpetual "Connecting..." UI state. Moot for the moment given the
  pivot below, but relevant if `mtproxy_relay.py` doesn't fully resolve
  it either.

### Path taken: `mtproxy_relay.py` (explicit MTProxy, not more reverse-engineering)

The user supplied the key piece of context that ended the guessing: **the
original upstream project, unmodified, with the standard secret-based
MTProxy protocol and a client explicitly configured via a `tg://proxy?...`
link, already worked correctly on both iPhone and Android before this
project adapted it into the transparent no-secret connector.** The
transparent mode was a usability nice-to-have (no client config needed),
not a requirement — and it's the thing that broke on Android, not the
underlying relay machinery.

Rather than continuing to reverse-engineer whatever TLS-shaped transport
unconfigured Android is actually using, added `relay/mtproxy_relay.py` +
vendored `relay/vendor/tg_ws_proxy.py` (the ORIGINAL upstream entry point,
completely unmodified — just imported as a module, same MIT vendoring
convention as the rest of `vendor/`) as a second, independent service.
Runs the real secret-based protocol on a public port; `transparent_relay.py`
is untouched and keeps running for iPhone (or anything else the no-secret
path works for). See README.md "Альтернатива: mtproxy_relay.py" for setup,
`tg-mtproxy-relay.service` for the systemd unit (requires
`ZTG_MTPROXY_SECRET`/`ZTG_MTPROXY_PORT` in `/etc/z2r_autobench/tgrelay.env`
— generate the secret once with `python3 -c "import os; print(os.urandom(16).hex())"`,
never let the service auto-generate one on every restart or every
configured client breaks).

**Not yet done on NETH-4 as of this writing:** actually deploying this
(picking a free port, generating+fixing the secret, installing the
systemd unit, generating the `tg://proxy?...` link/QR and configuring it
on the Android devices, end-to-end verification that Telegram actually
connects through it). That's the immediate next step for whoever picks
this up. Root cause of *why* `transparent_relay.py` fails on Android is
still open (see above) — this is a working mitigation, not a fix for the
transparent mode itself.

### How to reproduce the diagnostic capture

```bash
cd /opt/Zenith-TG
git pull origin main
systemctl stop tg-transparent-relay
cd relay
/opt/Zenith-TG/.venv/bin/python -u transparent_relay.py --host 127.0.0.1 --port 8447 -v
```
(Manual foreground run hits the shell's default `ulimit -n` under load —
saw `[Errno 24] Too many open files` during a flood of connections. The
systemd unit has its own higher limit and doesn't hit this; only matters
for manual `-v` debug runs like this one. Raise with `ulimit -n 65536`
in the same shell before running if it recurs.)

Reopen Telegram on the Android device while this is running, watch for
`non-MTProto handshake head: ...` lines. `Ctrl+C` when done, then
`systemctl start tg-transparent-relay` to restore normal operation —
don't leave the manual foreground run as the only thing serving this
port.

### Environment facts (for context, not secret)

- Android client app: Happ (Xray/VLESS-based). iOS: also Happ, same
  provider config, "preferred API type" defaults differ (IPv4 on iOS,
  was Auto on Android — now set to IPv4 on both).
  Confirmed YouTube/Instagram work fine over the same VLESS tunnel on
  Android — rules out a fully broken tunnel, base connectivity is fine.
- Server-side proxy panel: 3x-ui (`x-ui.service`).
- `_REAL_DC_IDS`, `DEFAULT_DC_IP`, and the `-v` hex-dump diagnostic are
  all in `relay/transparent_relay.py` as of commit `14135fc` (main
  branch, pushed directly — this repo doesn't currently use a designated
  feature branch the way z2r_autobench does).
