#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ──
# Set FIXTURES_DIR to the root of your extracted IPSW directory tree.
# Each entry below gives: test-binary fixture-path expected-vaddr
FIXTURES_DIR="${FIXTURES_DIR:-/mnt/stuff/Downloads/IPSW}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
mkdir -p "$BUILD_DIR"

CC="${CC:-gcc}"
CFLAGS_COMMON="-Wall -Wextra -Wno-unused-function -O1 -I$SCRIPT_DIR/compat -I$PROJECT_DIR/src -DTEST"

echo "=== Building test binaries ==="

$CC -m32 $CFLAGS_COMMON -D__arm__ '-D__ARM_ARCH=6' \
    "$SCRIPT_DIR/test_finder.c" -o "$BUILD_DIR/test_armv6"
echo "  Built test_armv6"

$CC -m32 $CFLAGS_COMMON -D__arm__ '-D__ARM_ARCH=7' \
    "$SCRIPT_DIR/test_finder.c" -o "$BUILD_DIR/test_armv7"
echo "  Built test_armv7"

$CC $CFLAGS_COMMON -D__arm64__ -D__LP64__ \
    "$SCRIPT_DIR/test_finder.c" -o "$BUILD_DIR/test_arm64"
echo "  Built test_arm64"

echo ""
echo "=== Running tests ==="

PASS=0
FAIL=0

run_test() {
    local binary="$1" fixture="$2" expected="$3" label="$4"
    if [ ! -f "$fixture" ]; then
        echo "SKIP  $label  (fixture not found: $fixture)"
        return
    fi
    if "$BUILD_DIR/$binary" "$fixture" "$expected"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
}

# armv6 — WiFiManager.bundle
run_test test_armv6 \
    "$FIXTURES_DIR/iPhone1,1_3.1.3_7E18_Restore/018-6482-014.out/SUNorthstarTwo7E18.iPhoneOS/System/Library/SystemConfiguration/WiFiManager.bundle/WiFiManager" \
    0x00023ed4 "iOS 3.1.3 armv6"

# iOS 4.2.1 is identical binary to 3.1.3, skip

# armv7 Thumb-16 — WiFiManager.bundle
run_test test_armv7 \
    "$FIXTURES_DIR/iPhone2,1_4.3.5_8L1_Restore/038-2287-002.out/Durango8L1.N88OS/System/Library/SystemConfiguration/WiFiManager.bundle/WiFiManager" \
    0x0002d8f8 "iOS 4.3.5 armv7-thumb16"

# armv7 Thumb-2 — wifid
run_test test_armv7 \
    "$FIXTURES_DIR/iPhone2,1_5.1.1_9B206_Restore/038-4355-009.out/Hoodoo9B206.N88OS/usr/sbin/wifid" \
    0x0004053c "iOS 5.1.1 armv7"

run_test test_armv7 \
    "$FIXTURES_DIR/iPhone2,1_6.1.6_10B500_Restore/048-2955-001.out/BrightonMaps10B500.N88OS/usr/sbin/wifid" \
    0x00054c18 "iOS 6.1.6 armv7"

run_test test_armv7 \
    "$FIXTURES_DIR/iPhone3,1_7.1.2_11D257_Restore/058-4520-010.out/Sochi11D257.N90OS/usr/sbin/wifid" \
    0x0006c500 "iOS 7.1.2 armv7"

run_test test_armv7 \
    "$FIXTURES_DIR/iPhone4,1_8.4.1_12H321_Restore/058-24033-023.out/Donner12H321.N94OS/usr/sbin/wifid" \
    0x000a0964 "iOS 8.4.1 armv7"

run_test test_armv7 \
    "$FIXTURES_DIR/iPhone4,1_9.3.6_13G37_Restore/058-48374-040.out/Genoa13G37.N94OS/usr/sbin/wifid" \
    0x000aa05c "iOS 9.3.6 armv7"

run_test test_armv7 \
    "$FIXTURES_DIR/iPhone_4.0_32bit_10.3.4_14G61_Restore/058-74968-065.out/1.disk image.hfsx.out/Greensburg14G61.N41N42N48N49OS/usr/sbin/wifid" \
    0x000c417e "iOS 10.3.4 armv7"

# arm64
run_test test_arm64 \
    "$FIXTURES_DIR/iPhone_4.0_64bit_10.3.3_14G60_Restore/058-74917-062.out/usr/sbin/wifid" \
    0x1000dbdf8 "iOS 10.3.3 arm64"

run_test test_arm64 \
    "$FIXTURES_DIR/iPhone_4.0_64bit_11.4.1_15G77_Restore/048-19581-075.out/usr/sbin/wifid" \
    0x100160aa0 "iOS 11.4.1 arm64"

run_test test_arm64 \
    "$FIXTURES_DIR/iPhone_5.5_12.5.8_16H88_Restore/038-87140-057.out/1.disk image.apfs.out/usr/sbin/wifid" \
    0x100175518 "iOS 12.5.8 arm64"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
