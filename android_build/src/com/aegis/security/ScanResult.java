package com.aegis.security;

import java.util.List;

public class ScanResult {
    public final String packageName;
    public final String appName;
    public final int riskScore;
    public final String verdict;
    public final List<String> threats;
    public final List<String> dangerousPermissions;

    public ScanResult(
        String packageName,
        String appName,
        int riskScore,
        String verdict,
        List<String> threats,
        List<String> dangerousPermissions
    ) {
        this.packageName = packageName;
        this.appName = appName;
        this.riskScore = riskScore;
        this.verdict = verdict;
        this.threats = threats;
        this.dangerousPermissions = dangerousPermissions;
    }
}
