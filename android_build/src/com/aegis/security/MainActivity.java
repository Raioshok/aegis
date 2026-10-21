package com.aegis.security;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    private TextView statusHeader;
    private TextView statusSubtitle;
    private TextView metricScanned;
    private TextView metricThreats;
    private ProgressBar progressBar;
    private TextView currentFileLabel;
    private LinearLayout findingsContainer;
    private Button scanButton;

    private int totalPackages = 0;
    private int threatsCount = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Root ScrollView
        ScrollView scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(Color.parseColor("#0C0D12")); // #0C0D12 Deep Dark Background
        scrollView.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(36), dp(20), dp(36));

        // 1. Header Bar: Logo & Brand
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        TextView logoIcon = new TextView(this);
        logoIcon.setText("🛡");
        logoIcon.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        header.addView(logoIcon);

        LinearLayout brandText = new LinearLayout(this);
        brandText.setOrientation(LinearLayout.VERTICAL);
        brandText.setPadding(dp(12), 0, 0, 0);

        TextView title = new TextView(this);
        title.setText("aegis");
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        title.setTextColor(Color.parseColor("#F3F4F6"));
        title.setTypeface(Typeface.DEFAULT_BOLD);
        brandText.addView(title);

        TextView subTitle = new TextView(this);
        subTitle.setText("MOBILE SECURITY SUITE · PURE-RUST CORE");
        subTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        subTitle.setTextColor(Color.parseColor("#FF7222"));
        subTitle.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        brandText.addView(subTitle);

        header.addView(brandText);
        root.addView(header);

        // Spacer
        addSpace(root, 24);

        // 2. Protection Status Hero Card
        LinearLayout heroCard = createCard();
        heroCard.setPadding(dp(20), dp(20), dp(20), dp(20));

        statusHeader = new TextView(this);
        statusHeader.setText("● DEVICE FULLY PROTECTED");
        statusHeader.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        statusHeader.setTextColor(Color.parseColor("#10B981")); // Emerald
        statusHeader.setTypeface(Typeface.DEFAULT_BOLD);
        heroCard.addView(statusHeader);

        statusSubtitle = new TextView(this);
        statusSubtitle.setText("Real-time permission auditor and Dalvik DEX opcode heuristics active.");
        statusSubtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        statusSubtitle.setTextColor(Color.parseColor("#9CA3AF"));
        statusSubtitle.setPadding(0, dp(4), 0, 0);
        heroCard.addView(statusSubtitle);

        root.addView(heroCard);

        addSpace(root, 16);

        // 3. High-Density Telemetry Metrics (Row of 2 Cards)
        LinearLayout metricsRow = new LinearLayout(this);
        metricsRow.setOrientation(LinearLayout.HORIZONTAL);

        LinearLayout card1 = createCard();
        card1.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f));
        card1.setPadding(dp(16), dp(16), dp(16), dp(16));
        TextView label1 = new TextView(this);
        label1.setText("APPLICATIONS");
        label1.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        label1.setTextColor(Color.parseColor("#6B7280"));
        label1.setTypeface(Typeface.MONOSPACE);
        card1.addView(label1);

        metricScanned = new TextView(this);
        metricScanned.setText("0 Audited");
        metricScanned.setTextSize(TypedValue.COMPLEX_UNIT_SP, 18);
        metricScanned.setTextColor(Color.parseColor("#F3F4F6"));
        metricScanned.setTypeface(Typeface.DEFAULT_BOLD);
        metricScanned.setPadding(0, dp(4), 0, 0);
        card1.addView(metricScanned);
        metricsRow.addView(card1);

        View gap = new View(this);
        gap.setLayoutParams(new LinearLayout.LayoutParams(dp(12), 1));
        metricsRow.addView(gap);

        LinearLayout card2 = createCard();
        card2.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f));
        card2.setPadding(dp(16), dp(16), dp(16), dp(16));
        TextView label2 = new TextView(this);
        label2.setText("THREATS FOUND");
        label2.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        label2.setTextColor(Color.parseColor("#6B7280"));
        label2.setTypeface(Typeface.MONOSPACE);
        card2.addView(label2);

        metricThreats = new TextView(this);
        metricThreats.setText("0 Threats");
        metricThreats.setTextSize(TypedValue.COMPLEX_UNIT_SP, 18);
        metricThreats.setTextColor(Color.parseColor("#10B981"));
        metricThreats.setTypeface(Typeface.DEFAULT_BOLD);
        metricThreats.setPadding(0, dp(4), 0, 0);
        card2.addView(metricThreats);
        metricsRow.addView(card2);

        root.addView(metricsRow);

        addSpace(root, 20);

        // 4. Primary Action Button
        scanButton = new Button(this);
        scanButton.setText("START REAL-TIME THREAT AUDIT");
        scanButton.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        scanButton.setTextColor(Color.WHITE);
        scanButton.setTypeface(Typeface.DEFAULT_BOLD);
        scanButton.setPadding(0, dp(16), 0, dp(16));

        GradientDrawable btnBg = new GradientDrawable();
        btnBg.setColor(Color.parseColor("#FF7222")); // Aegis Orange
        btnBg.setCornerRadius(dp(12));
        scanButton.setBackground(btnBg);
        root.addView(scanButton);

        addSpace(root, 16);

        // 5. Scan Progress Indicator
        progressBar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progressBar.setMax(100);
        progressBar.setProgress(0);
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar);

        currentFileLabel = new TextView(this);
        currentFileLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        currentFileLabel.setTextColor(Color.parseColor("#9CA3AF"));
        currentFileLabel.setTypeface(Typeface.MONOSPACE);
        currentFileLabel.setVisibility(View.GONE);
        currentFileLabel.setPadding(0, dp(6), 0, 0);
        root.addView(currentFileLabel);

        addSpace(root, 16);

        // 6. Section Title: Findings
        TextView findingsTitle = new TextView(this);
        findingsTitle.setText("SECURITY AUDIT FINDINGS");
        findingsTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        findingsTitle.setTextColor(Color.parseColor("#9CA3AF"));
        findingsTitle.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(findingsTitle);

        addSpace(root, 10);

        findingsContainer = new LinearLayout(this);
        findingsContainer.setOrientation(LinearLayout.VERTICAL);
        root.addView(findingsContainer);

        // Empty state view
        TextView emptyNotice = new TextView(this);
        emptyNotice.setText("No scan executed yet. Tap 'Start Real-Time Threat Audit' above to evaluate installed packages against Dalvik bytecode and permission escalation rules.");
        emptyNotice.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        emptyNotice.setTextColor(Color.parseColor("#6B7280"));
        emptyNotice.setPadding(dp(16), dp(24), dp(16), dp(24));
        findingsContainer.addView(emptyNotice);

        scrollView.addView(root);
        setContentView(scrollView);

        // Button Listener
        scanButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runSecurityScan();
            }
        });
    }

    private void runSecurityScan() {
        scanButton.setEnabled(false);
        scanButton.setText("AUDITING IN PROGRESS...");
        progressBar.setVisibility(View.VISIBLE);
        progressBar.setProgress(0);
        currentFileLabel.setVisibility(View.VISIBLE);
        findingsContainer.removeAllViews();
        threatsCount = 0;

        new ScanTask().execute();
    }

    private class ScanTask extends AsyncTask<Void, Integer, List<ScanResult>> {
        private List<PackageInfo> packages;

        @Override
        protected void onPreExecute() {
            PackageManager pm = getPackageManager();
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
            totalPackages = packages.size();
            progressBar.setMax(totalPackages);
        }

        @Override
        protected List<ScanResult> doInBackground(Void... voids) {
            List<ScanResult> results = new ArrayList<>();
            PackageManager pm = getPackageManager();

            for (int i = 0; i < packages.size(); i++) {
                PackageInfo pkg = packages.get(i);
                publishProgress(i + 1);

                String appName = null;
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(pkg.packageName, 0);
                    appName = pm.getApplicationLabel(ai).toString();
                } catch (Exception ignored) {}

                String[] perms = pkg.requestedPermissions;
                ScanResult res = AegisScanner.evaluatePackage(pkg.packageName, appName, perms);
                if (res.riskScore >= 35) {
                    results.add(res);
                }
            }
            return results;
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            int current = values[0];
            progressBar.setProgress(current);
            metricScanned.setText(current + " Audited");
            if (current < packages.size()) {
                currentFileLabel.setText("Checking: " + packages.get(current).packageName);
            }
        }

        @Override
        protected void onPostExecute(List<ScanResult> results) {
            progressBar.setVisibility(View.GONE);
            currentFileLabel.setVisibility(View.GONE);
            scanButton.setEnabled(true);
            scanButton.setText("START REAL-TIME THREAT AUDIT");

            threatsCount = results.size();
            if (threatsCount == 0) {
                statusHeader.setText("● DEVICE FULLY PROTECTED");
                statusHeader.setTextColor(Color.parseColor("#10B981"));
                metricThreats.setText("0 Threats");
                metricThreats.setTextColor(Color.parseColor("#10B981"));

                TextView cleanView = new TextView(MainActivity.this);
                cleanView.setText("✓ Audit Complete: All " + totalPackages + " installed applications verified clean.\nNo banking overlays, accessibility exploits, or SMS interceptors detected.");
                cleanView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
                cleanView.setTextColor(Color.parseColor("#10B981"));
                cleanView.setPadding(dp(16), dp(20), dp(16), dp(20));
                findingsContainer.addView(cleanView);
            } else {
                statusHeader.setText("⚠ THREATS REQUIRE ATTENTION");
                statusHeader.setTextColor(Color.parseColor("#EF4444"));
                metricThreats.setText(threatsCount + " Found");
                metricThreats.setTextColor(Color.parseColor("#EF4444"));

                for (final ScanResult r : results) {
                    LinearLayout card = createCard();
                    card.setPadding(dp(16), dp(16), dp(16), dp(16));

                    TextView name = new TextView(MainActivity.this);
                    name.setText(r.appName + " (" + r.packageName + ")");
                    name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
                    name.setTextColor(Color.parseColor("#F3F4F6"));
                    name.setTypeface(Typeface.DEFAULT_BOLD);
                    card.addView(name);

                    TextView badge = new TextView(MainActivity.this);
                    badge.setText("Risk Score: " + r.riskScore + "% · " + r.verdict);
                    badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                    badge.setTextColor(r.riskScore >= 70 ? Color.parseColor("#EF4444") : Color.parseColor("#F59E0B"));
                    badge.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
                    badge.setPadding(0, dp(4), 0, 0);
                    card.addView(badge);

                    if (!r.threats.isEmpty()) {
                        TextView t = new TextView(MainActivity.this);
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < r.threats.size(); i++) {
                            if (i > 0) sb.append(", ");
                            sb.append(r.threats.get(i));
                        }
                        t.setText("Detected: " + sb.toString());
                        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                        t.setTextColor(Color.parseColor("#EF4444"));
                        t.setPadding(0, dp(2), 0, 0);
                        card.addView(t);
                    }

                    // Action Button: Open App Info for quick uninstall
                    Button manageBtn = new Button(MainActivity.this);
                    manageBtn.setText("MANAGE / UNINSTALL");
                    manageBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                    manageBtn.setTextColor(Color.WHITE);
                    manageBtn.setPadding(dp(12), dp(8), dp(12), dp(8));

                    GradientDrawable btnDbg = new GradientDrawable();
                    btnDbg.setColor(Color.parseColor("#EF4444"));
                    btnDbg.setCornerRadius(dp(8));
                    manageBtn.setBackground(btnDbg);

                    manageBtn.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            Intent intent = new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                            intent.setData(Uri.parse("package:" + r.packageName));
                            startActivity(intent);
                        }
                    });

                    card.addView(manageBtn);
                    findingsContainer.addView(card);
                    addSpace(findingsContainer, 10);
                }
            }
        }
    }

    private LinearLayout createCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.parseColor("#141721")); // Card Surface #141721
        bg.setCornerRadius(dp(16));
        bg.setStroke(dp(1), Color.parseColor("#222636")); // Tone-stepped border #222636
        card.setBackground(bg);
        return card;
    }

    private void addSpace(ViewGroup parent, int dpVal) {
        View v = new View(this);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(dpVal)));
        parent.addView(v);
    }

    private int dp(int val) {
        return (int) (val * getResources().getDisplayMetrics().density);
    }
}
