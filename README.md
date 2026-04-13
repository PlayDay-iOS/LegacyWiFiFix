# WiFi Fix Old iOS

Fixes the RSN IE AKM-selection bug on iOS 3.x–12.x so transitional
WPA2/WPA3 networks (AP advertises both PSK and SAE) become associable
with a supported AKM (e.g. WPA2-PSK).

## The bug

Modern routers in WPA2/WPA3 transitional mode advertise both PSK (AKM 2)
and SAE (AKM 8) in the same RSN Information Element. Inside the AKM
selector (e.g. `_performAssociation`), iOS iterates `IE_KEY_RSN_AUTHSELS`
tracking the "best" AKM. When either the current best or the new candidate
is outside the table-driven range, the comparison falls back to raw value,
so a later unknown AKM (SAE = 8) overwrites an earlier known one (PSK = 2).
The switch on the selected AKM then hits `default:` and returns error
`-0xF3C`. Result: the whole network is refused even though WPA2-PSK would
have worked.

The accepted AKM range depends on the iOS version. The table below comes
from Ghidra decompilation of the switch inside `_performAssociation` in
stock `wifid` / `WiFiManager`:

| iOS         | Switch cases present | Max AKM |
|-------------|----------------------|---------|
| 3.x – 5.x   | 1, 2                 | 2       |
| 6.x – 7.x   | 1, 2, 3, 4           | 4       |
| 8.x – 12.x  | 1, 2, 3, 4, 5, 6     | 6       |

Verified directly against 3.1.3, 4.2.1, 4.3.5, 5.1.1, 6.1.6, 7.1.2,
8.4.1, 9.3.6, 10.3.3, 10.3.4, 11.4.1 and 12.5.8 binaries — every
major from iOS 3 through iOS 12 has at least one sampled point
release. The runtime picks `MAX_KNOWN_AKM` from
`kCFCoreFoundationVersionNumber`: ≥ iOS 8.0 → 6, ≥ iOS 6.0 → 4, else 2.

iOS 12.5.x added an explicit `(akm − 1) < 6` guard inside
`_performAssociation`'s main RSN loop, but a sibling function
(`FUN_100170a60` in 12.5.8 wifid) still uses the unguarded pattern and
rejects via its own 1..6 switch. The tweak is therefore still needed on
iOS 12.

## The fix

Hook `parseRSN_IE` and drop AKMs outside `1..MAX_KNOWN_AKM` from
`IE_KEY_RSN_AUTHSELS` before downstream code reads it. `MAX_KNOWN_AKM` is
chosen at load time from `kCFCoreFoundationVersionNumber` (`2` on iOS ≤ 5,
`4` on iOS 6 – 7, `6` on iOS ≥ 8).

## Building

The project uses [Theos](https://theos.dev) and builds inside a container so no
local iOS toolchain is required.

### Docker

```sh
# One-step build
docker compose up --build

# Or manually
docker build -t wififix-build -f Containerfile .
docker run --rm -v "$PWD:/build:Z" wififix-build
```

### Podman

```sh
# One-step build
podman-compose up --build

# Or manually
podman build -t wififix-build -f Containerfile .
podman run --rm -v "$PWD:/build:Z" wififix-build
```

The `.deb` package is written to `packages/`.

### Local

Install [Theos](https://theos.dev) (includes toolchain and SDK):

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
```

Install the iPhoneOS 12.4 SDK (required by the project):

```sh
$THEOS/bin/install-sdk iPhoneOS12.4
```

Then build:

```sh
make package FINALPACKAGE=1
```

## Installation

Copy the `.deb` to the device and install:

```sh
scp packages/*.deb root@<device>:/tmp/
ssh root@<device> 'dpkg -i /tmp/dev.playday3008.wififixoldios_*.deb'
```

The postinst script restarts `wifid` automatically so Substrate injects
into the new process — no `ldrestart` or reboot needed.

## Testing

A host-side harness runs the finder against real `wifid` /
`WiFiManager.bundle` binaries extracted from IPSWs, for every sampled
iOS version and every supported architecture (armv6, armv7, arm64).
It builds `test_finder.c` three times against stub Mach-O headers,
then invokes each build against its fixture and checks the resolved
parser address matches the expected VA.

Point `FIXTURES_DIR` at the root of your extracted IPSW tree and run:

```sh
FIXTURES_DIR=/path/to/ipsws test/run_tests.sh
```

Missing fixtures are reported as `SKIP`, so the suite can be run with a
partial set. The expected addresses in `test/run_tests.sh` come from
Ghidra decompilation of the stock binaries and must match exactly.

## How it works

The tweak injects into both `wifid` and the `WiFiManager.bundle` —
whichever image hosts the RSN IE parser on the running iOS version —
and locates the parser dynamically at runtime by:

1. Parsing the Mach-O header to find `__cstring` and `__cfstring` sections
2. Locating the CFString constants for `IE_KEY_RSN_VERSION` and
   `IE_KEY_RSN_AUTHSELS`
3. Decoding ARM instruction sequences to find code that references those
   constants — `ldr`-literal + `add pc` (ARM-mode armv6 and Thumb-16 on
   iOS 4.x, with their respective encodings), `movw`/`movt` + `add pc`
   on Thumb-2, and `adrp`/`add` (or linker-relaxed `adr`) on AArch64
4. Using a proximity heuristic to distinguish the parser from other functions
   that reference the same strings

After hooking, AKM suite selectors above the per-version `MAX_KNOWN_AKM`
are stripped from the parsed RSN IE, leaving only AKMs the running iOS
actually handles.
