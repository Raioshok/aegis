package com.aegis.security

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.graphics.Color
import android.view.Gravity

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 64)
            setBackgroundColor(Color.parseColor("#F6F8FB"))
        }

        val title = TextView(this).apply {
            text = "Aegis Mobile Security"
            textSize = 24f
            setTextColor(Color.parseColor("#1E293B"))
            setTypeface(null, android.graphics.Typeface.BOLD)
        }
        layout.addView(title)

        val subtitle = TextView(this).apply {
            text = "Real-Time Android Threat & Permission Auditing"
            textSize = 12f
            setTextColor(Color.parseColor("#64748B"))
            setPadding(0, 8, 0, 48)
        }
        layout.addView(subtitle)

        val scanButton = Button(this).apply {
            text = "Scan Installed Applications"
            setBackgroundColor(Color.parseColor("#FF7222"))
            setTextColor(Color.WHITE)
            setPadding(32, 24, 32, 24)
        }
        layout.addView(scanButton)

        val resultsView = TextView(this).apply {
            text = "Tap above to audit your device for banking trojans, SMS stealers, and unbacked overlays."
            textSize = 13f
            setTextColor(Color.parseColor("#475569"))
            setPadding(0, 32, 0, 0)
        }
        layout.addView(resultsView)

        scanButton.setOnClickListener {
            resultsView.text = "Scanning installed packages...\n"
            val pm = packageManager
            val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            var maliciousCount = 0

            for (pkg in packages) {
                val perms = pkg.requestedPermissions?.toList() ?: emptyList()
                val result = AegisScanner.evaluatePackage(pkg.packageName, perms, emptyList())
                if (result.riskScore >= 70) {
                    maliciousCount++
                    resultsView.append("\n⚠ ${result.packageName} — Risk: ${result.riskScore}% (${result.verdict})")
                }
            }

            if (maliciousCount == 0) {
                resultsView.append("\n\n✓ Scan Complete: All ${packages.size} installed packages verified clean.")
            } else {
                resultsView.append("\n\n⚠ Scan Complete: Found $maliciousCount suspicious packages requiring review.")
            }
        }

        setContentView(layout)
    }
}
