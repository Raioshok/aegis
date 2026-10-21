package com.aegis.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AegisScanner {
    private static final Map<String, Integer> PERMISSION_WEIGHTS = new HashMap<>();

    static {
        PERMISSION_WEIGHTS.put("android.permission.SEND_SMS", 25);
        PERMISSION_WEIGHTS.put("android.permission.RECEIVE_SMS", 25);
        PERMISSION_WEIGHTS.put("android.permission.READ_SMS", 20);
        PERMISSION_WEIGHTS.put("android.permission.SYSTEM_ALERT_WINDOW", 30);
        PERMISSION_WEIGHTS.put("android.permission.BIND_ACCESSIBILITY_SERVICE", 35);
        PERMISSION_WEIGHTS.put("android.permission.BIND_DEVICE_ADMIN", 30);
        PERMISSION_WEIGHTS.put("android.permission.REQUEST_INSTALL_PACKAGES", 20);
        PERMISSION_WEIGHTS.put("android.permission.RECORD_AUDIO", 15);
        PERMISSION_WEIGHTS.put("android.permission.CAMERA", 15);
        PERMISSION_WEIGHTS.put("android.permission.ACCESS_FINE_LOCATION", 15);
    }

    public static ScanResult evaluatePackage(
        String packageName,
        String appName,
        String[] permissions
    ) {
        int score = 0;
        List<String> threats = new ArrayList<>();
        List<String> dangerous = new ArrayList<>();

        boolean hasAccessibility = false;
        boolean hasOverlay = false;
        boolean hasSms = false;

        if (permissions != null) {
            for (String perm : permissions) {
                Integer weight = PERMISSION_WEIGHTS.get(perm);
                if (weight != null) {
                    score += weight;
                    dangerous.add(perm);
                }
                if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(perm)) {
                    hasAccessibility = true;
                }
                if ("android.permission.SYSTEM_ALERT_WINDOW".equals(perm)) {
                    hasOverlay = true;
                }
                if ("android.permission.RECEIVE_SMS".equals(perm) || "android.permission.SEND_SMS".equals(perm)) {
                    hasSms = true;
                }
            }
        }

        // Heuristic detection: Banking Trojan overlay & SMS interceptor pattern
        if (hasAccessibility && (hasOverlay || hasSms)) {
            score = Math.max(score, 90);
            threats.add("Trojan.AndroidOS.Banker (SharkBot / Godfather Heuristic)");
        }

        // Heuristic detection: Silent spy / background recording pattern
        if (dangerous.contains("android.permission.RECORD_AUDIO") && dangerous.contains("android.permission.ACCESS_FINE_LOCATION") && !dangerous.contains("android.permission.CAMERA")) {
            if (dangerous.size() > 5) {
                score = Math.max(score, 75);
                threats.add("Spyware.AndroidOS.AudioTracker");
            }
        }

        String verdict;
        if (score >= 70) {
            verdict = "Critical Threat";
        } else if (score >= 35) {
            verdict = "Suspicious Risk";
        } else {
            verdict = "Clean / Verified";
        }

        return new ScanResult(
            packageName,
            appName != null ? appName : packageName,
            Math.min(100, score),
            verdict,
            threats,
            dangerous
        );
    }
}
