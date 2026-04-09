# WiFi Fix Old iOS

Fixes WiFi connectivity to WPA2/WPA3 transitional networks on iOS 9.x–12.x.

Modern routers using WPA2/WPA3 transitional mode advertise both PSK (AKM 2)
and SAE (AKM 8) in their RSN Information Element. Older iOS `wifid` doesn't
recognize AKM 8, causing two failures:

1. The security type evaluator picks the highest AKM (8), which is out of the
   known range (1-6), marking the network security as unknown.
2. The association RSN element builder selects AKM 8, hits the default switch
   case, and aborts with error `-0xF3C`.

This tweak hooks the RSN IE parser and strips unknown AKM types (>= 7) after
parsing, so all downstream code only sees AKMs it understands. WPA2-PSK
association then proceeds normally.

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

Then restart wifid (or reboot):

```sh
ldrestart
```

## How it works

The tweak dynamically locates wifid's RSN IE parser at runtime by:

1. Parsing the Mach-O header to find `__cstring` and `__cfstring` sections
2. Locating the CFString constants for `IE_KEY_RSN_VERSION` and
   `IE_KEY_RSN_AUTHSELS`
3. Decoding ARM instruction sequences (`movw`/`movt`/`add pc` on Thumb-2,
   `adrp`/`add` on AArch64) to find code that references these constants
4. Using a proximity heuristic to distinguish the parser from other functions
   that reference the same strings

After hooking, any AKM suite selector >= 7 is stripped from the parsed RSN IE,
leaving only AKMs that older iOS understands (1-6).
