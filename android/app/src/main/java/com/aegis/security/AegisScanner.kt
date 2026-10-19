package com.aegis.security

data class ScanResult(
    val packageName: String,
    val riskScore: Int,
    val verdict: String,
    val threats: List<String>,
    val dangerousPermissions: List<String>
)

object AegisScanner {
    init {
        try {
            System.loadLibrary("aegis_android")
        } catch (e: UnsatisfiedLinkError) {
            // Fallback to pure Kotlin heuristic engine if native .so is loading
        }
    }

    external fun scanApkNative(apkPath: String): String
    external fun scanDexNative(dexBytes: ByteArray): String

    fun evaluatePackage(
        packageName: String,
        permissions: List<String>,
        signatures: List<String>
    ): ScanResult {
        var score = 0
        val threats = mutableListOf<String>()
        val dangerous = mutableListOf<String>()

        val highRiskPerms = mapOf(
            "android.permission.SEND_SMS" to 25,
            "android.permission.RECEIVE_SMS" to 25,
            "android.permission.SYSTEM_ALERT_WINDOW" to 30,
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to 35,
            "android.permission.BIND_DEVICE_ADMIN" to 30,
            "android.permission.REQUEST_INSTALL_PACKAGES" to 20
        )

        for (perm in permissions) {
            highRiskPerms[perm]?.let { weight ->
                score += weight
                dangerous.add(perm)
            }
        }

        val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasOverlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasSms = permissions.contains("android.permission.RECEIVE_SMS")

        if (hasAccessibility && (hasOverlay || hasSms)) {
            score = maxOf(score, 90)
            threats.add("Trojan.AndroidOS.Banker (Godfather / SharkBot)")
        }

        val verdict = when {
            score >= 70 -> "Malicious"
            score >= 35 -> "Suspicious"
            else -> "Safe"
        }

        return ScanResult(
            packageName = packageName,
            riskScore = minOf(100, score),
            verdict = verdict,
            threats = threats,
            dangerousPermissions = dangerous
        )
    }
}
