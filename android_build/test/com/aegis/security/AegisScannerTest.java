package com.aegis.security;

import java.util.Collections;
import java.util.Set;

/** Plain-JVM checks for the scan rules. Run: java -ea (see scripts/build_android_apk.sh). */
public class AegisScannerTest {
    private static AegisScanner.AppFacts app(String installer, String... perms) {
        AegisScanner.AppFacts a = new AegisScanner.AppFacts();
        a.packageName = "com.example.app";
        a.appName = "Example";
        a.requestedPermissions = perms;
        a.installer = installer;
        return a;
    }

    public static void main(String[] args) {
        Set<String> none = Collections.emptySet();

        ScanResult store = AegisScanner.evaluate(app("com.android.vending", "android.permission.CAMERA"), none);
        assert store.riskScore < AegisScanner.SUSPICIOUS : "store app with camera is not suspicious: " + store.riskScore;
        assert store.verdict.equals("No issues found");

        AegisScanner.AppFacts banker = app(null, "android.permission.SYSTEM_ALERT_WINDOW");
        banker.hasAccessibilityService = true;
        ScanResult b = AegisScanner.evaluate(banker, none);
        assert b.riskScore >= AegisScanner.DANGEROUS : "accessibility + overlay is dangerous: " + b.riskScore;
        assert b.threats.toString().contains("Banking-trojan") : b.threats.toString();

        // Accessibility alone, from a store, is common (password managers) and must not be "dangerous".
        AegisScanner.AppFacts a11y = app("com.android.vending");
        a11y.hasAccessibilityService = true;
        assert AegisScanner.evaluate(a11y, none).riskScore < AegisScanner.DANGEROUS;

        ScanResult smsThief = AegisScanner.evaluate(app("com.unknown.installer", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"), none);
        assert smsThief.riskScore >= AegisScanner.DANGEROUS : "sideloaded SMS sender: " + smsThief.riskScore;

        String hash = "AB".repeat(32);
        AegisScanner.AppFacts known = app("com.android.vending");
        known.apkSha256 = hash;
        Set<String> db = AegisScanner.parseHashList("# MalwareBazaar\n" + hash.toLowerCase() + "\nnot-a-hash\n");
        assert db.size() == 1 : "parser keeps only valid hashes";
        ScanResult k = AegisScanner.evaluate(known, db);
        assert k.riskScore == 100 && k.threats.get(0).startsWith("Matches a known malware") : k.threats.toString();

        System.out.println("AegisScannerTest: all checks passed");
    }
}
