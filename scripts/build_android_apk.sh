#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/mnt/c/Users/raio/Downloads/Telegram Desktop/Projects/aegis"
WORK_DIR="$BASE_DIR/android_build"
ANDROID_JAR="/usr/lib/android-sdk/platforms/android-23/android.jar"
BIN_DIR="$BASE_DIR/bin"

mkdir -p "$WORK_DIR/gen" "$WORK_DIR/obj" "$WORK_DIR/bin" "$BIN_DIR"

echo "=== 1. Generating R.java via aapt ==="
aapt package -f -m \
    -J "$WORK_DIR/gen" \
    -M "$WORK_DIR/AndroidManifest.xml" \
    -S "$WORK_DIR/res" \
    -I "$ANDROID_JAR"

echo "=== 2. Compiling Java sources via javac ==="
javac -source 8 -target 8 \
    -bootclasspath "$ANDROID_JAR" \
    -cp "$ANDROID_JAR" \
    -d "$WORK_DIR/obj" \
    "$WORK_DIR/gen/com/aegis/security/R.java" \
    "$WORK_DIR/src/com/aegis/security/ScanResult.java" \
    "$WORK_DIR/src/com/aegis/security/AegisScanner.java" \
    "$WORK_DIR/src/com/aegis/security/MainActivity.java"

DX_BIN="/usr/lib/android-sdk/build-tools/debian/dx"

echo "=== 3. Converting classes to classes.dex via dx ==="
"$DX_BIN" --dex --output="$WORK_DIR/bin/classes.dex" "$WORK_DIR/obj"

echo "=== 4. Packaging unaligned APK via aapt ==="
aapt package -f \
    -M "$WORK_DIR/AndroidManifest.xml" \
    -S "$WORK_DIR/res" \
    -I "$ANDROID_JAR" \
    -F "$WORK_DIR/bin/unaligned.apk"

echo "=== 5. Adding classes.dex to APK ==="
(cd "$WORK_DIR/bin" && aapt add unaligned.apk classes.dex)

echo "=== 6. Aligning APK byte boundaries via zipalign ==="
rm -f "$WORK_DIR/bin/aligned.apk"
zipalign -v -p 4 "$WORK_DIR/bin/unaligned.apk" "$WORK_DIR/bin/aligned.apk"

echo "=== 7. Creating Release Keystore ==="
KEYSTORE="$WORK_DIR/aegis-release.keystore"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkey -v \
        -keystore "$KEYSTORE" \
        -alias aegis \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -storepass aegispass \
        -keypass aegispass \
        -dname "CN=Aegis Mobile Security, OU=EDR Labs, O=Aegis, L=Porto Alegre, ST=RS, C=BR"
fi

echo "=== 8. Cryptographically signing APK via apksigner ==="
OUT_APK="$BIN_DIR/Aegis-Security.apk"
rm -f "$OUT_APK"
apksigner sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:aegispass \
    --out "$OUT_APK" \
    "$WORK_DIR/bin/aligned.apk"

echo "=== 9. Verifying APK cryptographic signature ==="
apksigner verify --verbose "$OUT_APK"

echo "=== SUCCESS: Android AV APK built at $OUT_APK ==="
ls -lh "$OUT_APK"
