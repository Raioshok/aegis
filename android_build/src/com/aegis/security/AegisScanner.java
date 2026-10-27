package com.aegis.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Risk rules for one installed app. Pure Java (no android.* imports) so the
 * rules can be unit-tested on a desktop JVM; MainActivity gathers the facts.
 */
public class AegisScanner {

    /** Facts about one installed app, read from PackageManager. */
    public static class AppFacts {
        public String packageName;
        public String appName;
        public String[] requestedPermissions;
        /** Declares a service guarded by BIND_ACCESSIBILITY_SERVICE (can read and drive other apps' screens). */
        public boolean hasAccessibilityService;
        /** Declares a receiver guarded by BIND_DEVICE_ADMIN (can lock or wipe the device, resist uninstall). */
        public boolean hasDeviceAdmin;
        /** Installer package name, or null when installed from a file (sideloaded). */
        public String installer;
        /** SHA-256 of the base APK, or null when not computed. */
        public String apkSha256;
    }

    private static final Map<String, Integer> PERMISSION_WEIGHTS = new HashMap<>();
    static {
        PERMISSION_WEIGHTS.put("android.permission.SEND_SMS", 20);
        PERMISSION_WEIGHTS.put("android.permission.RECEIVE_SMS", 20);
        PERMISSION_WEIGHTS.put("android.permission.READ_SMS", 20);
        PERMISSION_WEIGHTS.put("android.permission.SYSTEM_ALERT_WINDOW", 20);
        PERMISSION_WEIGHTS.put("android.permission.REQUEST_INSTALL_PACKAGES", 15);
        PERMISSION_WEIGHTS.put("android.permission.READ_CALL_LOG", 10);
        PERMISSION_WEIGHTS.put("android.permission.READ_CONTACTS", 5);
        PERMISSION_WEIGHTS.put("android.permission.RECORD_AUDIO", 5);
        PERMISSION_WEIGHTS.put("android.permission.CAMERA", 5);
        PERMISSION_WEIGHTS.put("android.permission.ACCESS_FINE_LOCATION", 5);
    }

    /** App stores whose installs are reviewed; anything else counts as sideloaded. */
    private static final Set<String> STORES = new HashSet<>(Arrays.asList(
        "com.android.vending",
        "com.amazon.venezia",
        "com.sec.android.app.samsungapps",
        "com.huawei.appmarket",
        "com.xiaomi.market",
        "org.fdroid.fdroid"
    ));

    public static final int SUSPICIOUS = 35;
    public static final int DANGEROUS = 70;

    public static ScanResult evaluate(AppFacts app, Set<String> knownMalwareSha256) {
        int score = 0;
        List<String> reasons = new ArrayList<>();
        List<String> risky = new ArrayList<>();

        Set<String> perms = new HashSet<>();
        if (app.requestedPermissions != null) {
            perms.addAll(Arrays.asList(app.requestedPermissions));
        }
        for (String p : perms) {
            Integer w = PERMISSION_WEIGHTS.get(p);
            if (w != null) {
                score += w;
                risky.add(p.substring(p.lastIndexOf('.') + 1));
            }
        }

        boolean sms = perms.contains("android.permission.RECEIVE_SMS") || perms.contains("android.permission.READ_SMS");
        boolean overlay = perms.contains("android.permission.SYSTEM_ALERT_WINDOW");
        boolean sideloaded = app.installer == null || !STORES.contains(app.installer);

        if (app.hasAccessibilityService) {
            score += 15;
            reasons.add("Has an accessibility service (can read and control other apps)");
        }
        if (app.hasDeviceAdmin) {
            score += 15;
            reasons.add("Can become device administrator");
        }
        if (sideloaded) {
            score += 10;
            reasons.add(app.installer == null ? "Installed from a file, not an app store" : "Installed by " + app.installer);
        }
        // Banking trojans pair screen control with overlays or SMS code theft.
        if (app.hasAccessibilityService && (overlay || sms)) {
            score = Math.max(score, DANGEROUS + 5);
            reasons.add("Banking-trojan pattern: accessibility control plus " + (overlay ? "screen overlays" : "SMS access"));
        }
        if (sideloaded && sms && perms.contains("android.permission.SEND_SMS")) {
            score = Math.max(score, DANGEROUS);
            reasons.add("Sideloaded app that can read and send SMS");
        }
        if (app.apkSha256 != null && knownMalwareSha256 != null && knownMalwareSha256.contains(app.apkSha256.toLowerCase())) {
            score = 100;
            reasons.add(0, "Matches a known malware sample (MalwareBazaar)");
        }

        score = Math.min(100, score);
        String verdict = score >= DANGEROUS ? "Dangerous" : score >= SUSPICIOUS ? "Suspicious" : "No issues found";
        return new ScanResult(app.packageName, app.appName != null ? app.appName : app.packageName, score, verdict, reasons, risky);
    }

    /** Parse a MalwareBazaar-style list: one SHA-256 per line, '#' comments. */
    public static Set<String> parseHashList(String text) {
        Set<String> out = new HashSet<>();
        for (String line : text.split("\n")) {
            String h = line.trim().toLowerCase();
            if (h.length() == 64 && h.matches("[0-9a-f]{64}")) {
                out.add(h);
            }
        }
        return out;
    }
}
