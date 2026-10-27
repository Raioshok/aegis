package com.aegis.security;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.format.DateUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final String MALWARE_FEED = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
    private static final String DB_FILE = "malware_sha256.txt";

    // Palette follows the system light/dark setting.
    private int bg, surface, line, fg, muted, brand, brandSoft, ok, okSoft, warn, warnSoft, danger, dangerSoft;

    private LinearLayout statusCard;
    private TextView statusTitle, statusText, statApps, statRisky, statDb;
    private ProgressBar progress;
    private TextView progressLabel;
    private Button scanButton, updateButton;
    private LinearLayout findings;
    private volatile boolean busy;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        boolean dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        bg = Color.parseColor(dark ? "#0B0F14" : "#F2F5F8");
        surface = Color.parseColor(dark ? "#131921" : "#FFFFFF");
        line = Color.parseColor(dark ? "#242D39" : "#E2E7ED");
        fg = Color.parseColor(dark ? "#E8EDF2" : "#16202B");
        muted = Color.parseColor(dark ? "#94A1AF" : "#586573");
        brand = Color.parseColor(dark ? "#26C49B" : "#009678");
        brandSoft = Color.parseColor(dark ? "#0F2C25" : "#E4F5EF");
        ok = Color.parseColor(dark ? "#34CD8C" : "#109660");
        okSoft = Color.parseColor(dark ? "#0E2A1F" : "#E6F6EE");
        warn = Color.parseColor(dark ? "#F5B546" : "#C47600");
        warnSoft = Color.parseColor(dark ? "#30240E" : "#FDF3E0");
        danger = Color.parseColor(dark ? "#F87171" : "#D43838");
        dangerSoft = Color.parseColor(dark ? "#341618" : "#FCECEC");
        getWindow().setStatusBarColor(bg);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(bg);
        scroll.setFillViewport(true);
        LinearLayout root = vertical();
        root.setPadding(dp(20), dp(28), dp(20), dp(28));
        scroll.addView(root);

        TextView title = text("Aegis", 24, fg, true);
        root.addView(title);
        root.addView(text("App security scanner", 13, muted, false));
        space(root, 20);

        statusCard = card(brandSoft);
        statusTitle = text("Not scanned yet", 20, fg, true);
        statusText = text("Scan checks every app you installed for banking-trojan and SMS-theft patterns, device-admin rights, "
            + "sideloading and, once the malware database is downloaded, known malware samples.", 13, muted, false);
        statusText.setPadding(0, dp(6), 0, 0);
        statusCard.addView(statusTitle);
        statusCard.addView(statusText);
        root.addView(statusCard);
        space(root, 12);

        LinearLayout stats = new LinearLayout(this);
        stats.setOrientation(LinearLayout.HORIZONTAL);
        statApps = stat(stats, "Apps checked", "—");
        statRisky = stat(stats, "Need attention", "—");
        statDb = stat(stats, "Malware database", "—");
        root.addView(stats);
        space(root, 16);

        scanButton = button("Scan apps", brand, Color.WHITE);
        root.addView(scanButton);
        space(root, 8);
        updateButton = button("Update malware database", surface, fg);
        ((GradientDrawable) updateButton.getBackground()).setStroke(dp(1), line);
        root.addView(updateButton);
        space(root, 12);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setVisibility(View.GONE);
        root.addView(progress);
        progressLabel = text("", 12, muted, false);
        progressLabel.setVisibility(View.GONE);
        root.addView(progressLabel);
        space(root, 12);

        findings = vertical();
        root.addView(findings);
        setContentView(scroll);

        scanButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { startScan(); } });
        updateButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { startDbUpdate(); } });
        refreshDbStat();
    }

    // --- Malware database -------------------------------------------------

    private File dbFile() {
        return new File(getFilesDir(), DB_FILE);
    }

    private Set<String> loadDb() {
        File f = dbFile();
        if (!f.exists()) return Collections.emptySet();
        try (InputStream in = new FileInputStream(f)) {
            byte[] data = new byte[(int) f.length()];
            int off = 0;
            while (off < data.length) {
                int n = in.read(data, off, data.length - off);
                if (n < 0) break;
                off += n;
            }
            return AegisScanner.parseHashList(new String(data, 0, off, "UTF-8"));
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    private void refreshDbStat() {
        File f = dbFile();
        if (!f.exists()) {
            statDb.setText("Not downloaded");
        } else {
            statDb.setText(DateUtils.getRelativeTimeSpanString(f.lastModified()).toString());
        }
    }

    private void startDbUpdate() {
        if (busy) return;
        setBusy(true, "Downloading malware database…");
        new Thread(new Runnable() { @Override public void run() {
            String error = null;
            int count = 0;
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(MALWARE_FEED).openConnection();
                c.setConnectTimeout(15000);
                c.setReadTimeout(60000);
                if (c.getResponseCode() != 200) throw new Exception("server answered " + c.getResponseCode());
                StringBuilder sb = new StringBuilder();
                try (InputStream in = c.getInputStream()) {
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = in.read(buf)) > 0) sb.append(new String(buf, 0, n, "UTF-8"));
                }
                Set<String> hashes = AegisScanner.parseHashList(sb.toString());
                if (hashes.isEmpty()) throw new Exception("download contained no hashes");
                // Write to a temp file first so a failed download never replaces a good database.
                File tmp = new File(getFilesDir(), DB_FILE + ".tmp");
                try (FileOutputStream out = new FileOutputStream(tmp)) {
                    out.write(join("\n", hashes).getBytes("UTF-8"));
                }
                if (!tmp.renameTo(dbFile())) throw new Exception("could not save database");
                count = hashes.size();
            } catch (Exception e) {
                error = e.getMessage();
            }
            final String err = error;
            final int n = count;
            runOnUiThread(new Runnable() { @Override public void run() {
                setBusy(false, null);
                refreshDbStat();
                showNote(err == null ? "Malware database updated: " + n + " sample hashes." : "Update failed: " + err, err == null ? ok : danger);
            } });
        } }).start();
    }

    // --- Scan ------------------------------------------------------------------

    private void startScan() {
        if (busy) return;
        setBusy(true, "Reading installed apps…");
        findings.removeAllViews();
        new Thread(new Runnable() { @Override public void run() {
            PackageManager pm = getPackageManager();
            int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS;
            List<PackageInfo> all = pm.getInstalledPackages(flags);
            final List<PackageInfo> apps = new ArrayList<>();
            for (PackageInfo p : all) {
                ApplicationInfo ai = p.applicationInfo;
                boolean system = ai != null && (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                    && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
                if (!system && !p.packageName.equals(getPackageName())) apps.add(p);
            }
            Set<String> db = loadDb();
            final List<ScanResult> risky = new ArrayList<>();
            for (int i = 0; i < apps.size(); i++) {
                PackageInfo p = apps.get(i);
                final int done = i;
                final String name = p.packageName;
                final int total = apps.size();
                runOnUiThread(new Runnable() { @Override public void run() {
                    progress.setMax(total);
                    progress.setProgress(done);
                    progressLabel.setText("Checking " + name);
                } });
                ScanResult r = AegisScanner.evaluate(facts(pm, p, !db.isEmpty()), db);
                if (r.riskScore >= AegisScanner.SUSPICIOUS) risky.add(r);
            }
            Collections.sort(risky, new Comparator<ScanResult>() {
                @Override
                public int compare(ScanResult a, ScanResult b) {
                    return b.riskScore - a.riskScore;
                }
            });
            final boolean usedDb = !db.isEmpty();
            final int checked = apps.size();
            runOnUiThread(new Runnable() { @Override public void run() { showResults(checked, risky, usedDb); } });
        } }).start();
    }

    private AegisScanner.AppFacts facts(PackageManager pm, PackageInfo p, boolean hash) {
        AegisScanner.AppFacts f = new AegisScanner.AppFacts();
        f.packageName = p.packageName;
        f.requestedPermissions = p.requestedPermissions;
        if (p.applicationInfo != null) {
            f.appName = pm.getApplicationLabel(p.applicationInfo).toString();
            if (hash && p.applicationInfo.sourceDir != null) f.apkSha256 = sha256(new File(p.applicationInfo.sourceDir));
        }
        if (p.services != null) {
            for (ServiceInfo s : p.services) {
                if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission)) f.hasAccessibilityService = true;
            }
        }
        if (p.receivers != null) {
            for (ActivityInfo r : p.receivers) {
                if ("android.permission.BIND_DEVICE_ADMIN".equals(r.permission)) f.hasDeviceAdmin = true;
            }
        }
        try {
            f.installer = pm.getInstallerPackageName(p.packageName);
        } catch (IllegalArgumentException ignored) {
            f.installer = null;
        }
        return f;
    }

    private static String sha256(File file) {
        try (InputStream in = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void showResults(int checked, List<ScanResult> risky, boolean usedDb) {
        setBusy(false, null);
        statApps.setText(String.valueOf(checked));
        statRisky.setText(String.valueOf(risky.size()));
        boolean dangerous = !risky.isEmpty() && risky.get(0).riskScore >= AegisScanner.DANGEROUS;
        if (risky.isEmpty()) {
            setStatus(okSoft, "No risky apps found", "Checked " + checked + " installed apps."
                + (usedDb ? "" : " Download the malware database to also match known malware samples."));
        } else {
            setStatus(dangerous ? dangerSoft : warnSoft, risky.size() + (risky.size() == 1 ? " app needs" : " apps need") + " attention",
                "Review the apps below. Uninstall any you do not recognise.");
        }
        for (ScanResult r : risky) findings.addView(findingCard(r));
    }

    private View findingCard(final ScanResult r) {
        LinearLayout c = card(surface);
        boolean danger_ = r.riskScore >= AegisScanner.DANGEROUS;
        c.addView(text(r.appName, 15, fg, true));
        TextView pkg = text(r.packageName, 12, muted, false);
        c.addView(pkg);
        TextView verdict = text(r.verdict + " · risk " + r.riskScore + "/100", 12, danger_ ? danger : warn, true);
        verdict.setPadding(0, dp(6), 0, dp(4));
        c.addView(verdict);
        for (String reason : r.threats) c.addView(text("• " + reason, 13, fg, false));
        if (!r.dangerousPermissions.isEmpty()) {
            TextView perms = text("Permissions: " + join(", ", r.dangerousPermissions), 12, muted, false);
            perms.setPadding(0, dp(4), 0, 0);
            c.addView(perms);
        }
        Button info = button("App info / uninstall", danger_ ? danger : surface, danger_ ? Color.WHITE : fg);
        if (!danger_) ((GradientDrawable) info.getBackground()).setStroke(dp(1), line);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        info.setLayoutParams(lp);
        info.setPadding(dp(16), 0, dp(16), 0);
        info.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent i = new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                i.setData(Uri.parse("package:" + r.packageName));
                startActivity(i);
            }
        });
        c.addView(info);
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cp.bottomMargin = dp(10);
        c.setLayoutParams(cp);
        return c;
    }

    // --- UI helpers ---------------------------------------------------------------

    private void setBusy(boolean on, String label) {
        busy = on;
        scanButton.setEnabled(!on);
        updateButton.setEnabled(!on);
        scanButton.setAlpha(on ? 0.5f : 1f);
        updateButton.setAlpha(on ? 0.5f : 1f);
        progress.setVisibility(on ? View.VISIBLE : View.GONE);
        progress.setIndeterminate(label != null && label.startsWith("Downloading"));
        progressLabel.setVisibility(on ? View.VISIBLE : View.GONE);
        if (label != null) progressLabel.setText(label);
    }

    private void setStatus(int tint, String title, String body) {
        ((GradientDrawable) statusCard.getBackground()).setColor(tint);
        statusTitle.setText(title);
        statusText.setText(body);
    }

    private void showNote(String msg, int color) {
        TextView t = text(msg, 13, color, false);
        t.setPadding(0, 0, 0, dp(10));
        findings.addView(t, 0);
    }

    private LinearLayout vertical() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    private LinearLayout card(int color) {
        LinearLayout c = vertical();
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(16));
        d.setStroke(dp(1), line);
        c.setBackground(d);
        c.setPadding(dp(18), dp(16), dp(18), dp(16));
        return c;
    }

    private TextView stat(LinearLayout row, String label, String value) {
        LinearLayout c = card(surface);
        c.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        if (row.getChildCount() > 0) lp.leftMargin = dp(8);
        c.setLayoutParams(lp);
        c.addView(text(label, 11, muted, false));
        TextView v = text(value, 15, fg, true);
        v.setPadding(0, dp(4), 0, 0);
        c.addView(v);
        row.addView(c);
        return v;
    }

    private Button button(String label, int color, int textColor) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setTextColor(textColor);
        b.setMinHeight(dp(48));
        b.setGravity(Gravity.CENTER);
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(12));
        b.setBackground(d);
        return b;
    }

    private TextView text(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private void space(ViewGroup parent, int dpVal) {
        View v = new View(this);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(dpVal)));
        parent.addView(v);
    }

    private static String join(String sep, Iterable<String> items) {
        StringBuilder sb = new StringBuilder();
        for (String s : items) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(s);
        }
        return sb.toString();
    }

    private int dp(int val) {
        return (int) (val * getResources().getDisplayMetrics().density);
    }
}
