package com.fartlos21.controller;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.Manifest;
import android.view.Gravity;
import android.view.View;
import android.widget.*;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import android.content.Context;
import android.graphics.drawable.Drawable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final String CHANNEL_ID = "fart_status";
    private static final String PREFS = "settings";
    private static final String KEY_EXPORT_DIR = "export_dir";
    private static final String KEY_ALLOWED_PACKAGES = "allowed_packages";
    private TextView statusText, statsText, dumpStatusText;
    private Button selectBtn, startBtn, exportBtn, refreshBtn, exportDirBtn, logBtn;
    private String selectedPkg = "";
    private String selectedName = "";
    private Switch activeSwitch = null;
    private String exportBaseDir = "/sdcard/FART-LOS21";
    private HashSet<String> allowedPackages = new HashSet<>();
    private HashSet<String> packageNames = new HashSet<>();
    private String lastDumpStatus = "";
    private boolean suppressSwitchEvents = false;
    private Handler handler = new Handler();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        RootShell.dataDir = getFilesDir().getPath();
        exportBaseDir = getPreferences(MODE_PRIVATE).getString(KEY_EXPORT_DIR, exportBaseDir);
        allowedPackages.addAll(getPreferences(MODE_PRIVATE).getStringSet(KEY_ALLOWED_PACKAGES, new HashSet<>()));
        initNotifications();

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(40, 40, 40, 40);
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("FART-LOS21 脱壳工具");
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        statusText = new TextView(this);
        statusText.setText("模块状态: 检测中...");
        statusText.setTextSize(14);
        root.addView(statusText);

        selectBtn = new Button(this);
        selectBtn.setText("选择目标应用");
        selectBtn.setTextSize(14);
        root.addView(selectBtn);
        selectBtn.setOnClickListener(v -> showAppList());

        LinearLayout infoBox = new LinearLayout(this);
        infoBox.setOrientation(LinearLayout.VERTICAL);
        infoBox.setPadding(20, 20, 20, 20);
        infoBox.setBackgroundColor(0x22FFFFFF);
        root.addView(infoBox);

        String[] infos = {
            "✓ 拦截 DefineClass 实时 dump DEX",
            "✓ Hook ArtMethod::Invoke 捕获 CodeItem",
            "✓ 主动调用触发加壳方法解密",
            "✓ 模块 service.sh 自动搬运配置"
        };
        for (String s : infos) {
            TextView tv = new TextView(this);
            tv.setText(s);
            tv.setTextSize(13);
            infoBox.addView(tv);
        }

        startBtn = new Button(this);
        startBtn.setText("允许脱壳");
        startBtn.setTextSize(20);
        startBtn.setPadding(0, 20, 0, 20);
        root.addView(startBtn);
        startBtn.setOnClickListener(v -> showDumpSwitch());

        statsText = new TextView(this);
        statsText.setText("Dex: 0  |  CodeItem: 0");
        statsText.setPadding(0, 20, 0, 0);
        root.addView(statsText);

        dumpStatusText = new TextView(this);
        dumpStatusText.setText("脱壳状态: 未开始");
        dumpStatusText.setTextSize(13);
        root.addView(dumpStatusText);

        exportBtn = new Button(this);
        exportBtn.setText("导出 DEX");
        root.addView(exportBtn);
        exportBtn.setOnClickListener(v -> exportDump());

        exportDirBtn = new Button(this);
        exportDirBtn.setText("导出目录: " + exportBaseDir);
        root.addView(exportDirBtn);
        exportDirBtn.setOnClickListener(v -> showExportDirDialog());

        logBtn = new Button(this);
        logBtn.setText("导出日志");
        root.addView(logBtn);
        logBtn.setOnClickListener(v -> exportLogs());

        refreshBtn = new Button(this);
        refreshBtn.setText("刷新统计");
        root.addView(refreshBtn);
        refreshBtn.setOnClickListener(v -> refresh());

        setContentView(scroll);
        refresh();
        handler.postDelayed(this::pollStatus, 3000);
    }

    private void showAppList() {
        List<ApplicationInfo> apps = getPackageManager().getInstalledApplications(0);
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(12);
        list.setPadding(pad, pad, pad, pad);

        for (ApplicationInfo ai : apps) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            packageNames.add(ai.packageName);
            list.addView(createAppRow(ai));
        }

        ScrollView listScroll = new ScrollView(this);
        listScroll.addView(list);

        new AlertDialog.Builder(this)
            .setTitle("选择目标应用")
            .setView(listScroll)
            .show();
    }

    private View createAppRow(ApplicationInfo ai) {
        String name = getPackageManager().getApplicationLabel(ai).toString();
        String pkg = ai.packageName;

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(8), 0, dp(8));

        ImageView icon = new ImageView(this);
        Drawable drawable = getPackageManager().getApplicationIcon(ai);
        icon.setImageDrawable(drawable);
        row.addView(icon, new LinearLayout.LayoutParams(dp(42), dp(42)));

        LinearLayout textBox = new LinearLayout(this);
        textBox.setOrientation(LinearLayout.VERTICAL);
        textBox.setPadding(dp(12), 0, dp(12), 0);
        TextView nameView = new TextView(this);
        nameView.setText(name);
        nameView.setTextSize(16);
        TextView pkgView = new TextView(this);
        pkgView.setText(pkg);
        pkgView.setTextSize(12);
        textBox.addView(nameView);
        textBox.addView(pkgView);
        row.addView(textBox, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));

        Switch sw = new Switch(this);
        sw.setChecked(allowedPackages.contains(pkg));
        row.addView(sw);

        View.OnClickListener select = v -> {
            selectedPkg = pkg;
            selectedName = name;
            selectBtn.setText(selectedName);
            refresh();
        };
        row.setOnClickListener(select);
        textBox.setOnClickListener(select);
        icon.setOnClickListener(select);
        sw.setOnCheckedChangeListener((button, checked) -> {
            if (suppressSwitchEvents) return;
            selectedPkg = pkg;
            selectedName = name;
            selectBtn.setText(selectedName);
            activeSwitch = (Switch)button;
            if (checked) {
                allowedPackages.add(pkg);
                writeDumpConfig();
            } else {
                allowedPackages.remove(pkg);
                writeDisableConfig();
            }
        });
        return row;
    }

    private void refresh() {
        boolean ok = RootShell.isModuleInstalled();
        statusText.setText("模块状态: " + (ok ? "✓ 已安装" : "✗ 未检测到（需重启后生效）"));
        String s = RootShell.getStats();
        String[] parts = s.split("\\|");
        String dex = (parts.length > 0 ? parts[0] : "0");
        String code = (parts.length > 2 ? parts[2] : "0");
        statsText.setText("Dex: " + dex + "  |  CodeItem: " + code);
        String dumpStatus = RootShell.getDumpStatus();
        String displayStatus = dumpStatus.isEmpty() ? "未开始" : dumpStatus;
        dumpStatusText.setText("脱壳状态: " + displayStatus);
        if (!dumpStatus.isEmpty() && !dumpStatus.equals(lastDumpStatus)) {
            lastDumpStatus = dumpStatus;
            notifyStatus("脱壳状态", dumpStatus);
        }
    }

    private void showDumpSwitch() {
        if (selectedPkg.isEmpty()) {
            Toast.makeText(this, "请先选择目标应用", Toast.LENGTH_SHORT).show();
            return;
        }

        new AlertDialog.Builder(this)
            .setTitle(selectedName)
            .setItems(new String[]{"允许脱壳", "关闭脱壳，正常启动"}, (dialog, which) -> {
                if (which == 0) {
                    allowedPackages.add(selectedPkg);
                    writeDumpConfig();
                } else {
                    allowedPackages.remove(selectedPkg);
                    writeDisableConfig();
                }
            })
            .show();
    }

    private void writeDumpConfig() {
        if (selectedPkg.isEmpty()) {
            Toast.makeText(this, "请先选择目标应用", Toast.LENGTH_SHORT).show();
            return;
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"enable\":true,");
        json.append("\"packages\":").append(buildPackagesJson()).append(",");
        json.append("\"dump_dir\":\"/data/local/tmp/fart_dump\",\"dump_dex\":true,");
        json.append("\"enable_artmethod_hook\":true,\"artmethod_sample_rate\":100,");
        json.append("\"enable_codeitem_dump\":true,\"max_codeitem_dumps\":2000,");
        json.append("\"enable_active_invoke\":true,");
        json.append("\"active_invoke_delay_ms\":1000,\"active_invoke_max_methods\":500,");
        json.append("\"active_invoke_skip_execute\":true,");
        json.append("\"active_invoke_classes\":[]}");

        if (RootShell.writeConfig(json.toString())) {
            saveAllowedPackages();
            RootShell.writeLocalStatus("已允许脱壳，等待目标应用启动");
            RootShell.writeAutoExport(selectedPkg, normalizeExportDir(exportBaseDir));
            // Force-stop via service.sh (root needed for am)
            RootShell.writeLaunchTrigger(selectedPkg);
            startBtn.setText("关闭脱壳，正常启动");
            notifyStatus("已允许脱壳", "已停止 " + selectedName + "，重新打开即可脱壳");
            Toast.makeText(this, "已停止 " + selectedName + "，重新打开即可自动脱壳", Toast.LENGTH_LONG).show();
            new Handler().postDelayed(() -> refresh(), 5000);
        } else {
            Toast.makeText(this, "写入失败", Toast.LENGTH_LONG).show();
        }
    }

    private void writeDisableConfig() {
        boolean stillEnabled = !allowedPackages.isEmpty();
        String json = "{\"enable\":" + stillEnabled + ",\"packages\":" + buildPackagesJson() + ","
            + "\"dump_dir\":\"/data/local/tmp/fart_dump\",\"dump_dex\":" + stillEnabled + ","
            + "\"enable_artmethod_hook\":" + stillEnabled + ",\"enable_codeitem_dump\":" + stillEnabled + ","
            + "\"enable_active_invoke\":" + stillEnabled + ",\"active_invoke_classes\":[]}";

        if (RootShell.writeConfig(json)) {
            saveAllowedPackages();
            RootShell.writeLocalStatus("已关闭脱壳，目标应用将正常启动");
            startBtn.setText(stillEnabled ? "允许表已更新" : "允许脱壳");
            notifyStatus("已关闭脱壳", "目标应用将正常启动");
            Toast.makeText(this, "已关闭脱壳。请完全退出目标应用后再正常启动", Toast.LENGTH_LONG).show();
            new Handler().postDelayed(() -> refresh(), 2000);
        } else {
            Toast.makeText(this, "关闭失败", Toast.LENGTH_LONG).show();
        }
    }

    private void exportDump() {
        if (selectedPkg.isEmpty()) {
            Toast.makeText(this, "请先选择目标应用", Toast.LENGTH_SHORT).show();
            return;
        }

        String[] parts = RootShell.getStats().split("\\|");
        int dex = parseInt(parts.length > 0 ? parts[0] : "0");
        int code = parseInt(parts.length > 2 ? parts[2] : "0");
        if (dex == 0 && code == 0) {
            Toast.makeText(this, "未发现 dump 文件，请先打开目标应用并刷新统计", Toast.LENGTH_LONG).show();
            return;
        }

        String exportDir = normalizeExportDir(exportBaseDir);
        if (!RootShell.exportDump(selectedPkg, exportDir)) {
            Toast.makeText(this, "导出请求写入失败", Toast.LENGTH_LONG).show();
            notifyStatus("导出失败", "导出请求写入失败");
            return;
        }

        Toast.makeText(this, "导出请求已发送，等待模块处理", Toast.LENGTH_SHORT).show();
        notifyStatus("导出请求已发送", exportDir + "/" + selectedPkg);
        new Handler().postDelayed(this::showExportResult, 2500);
    }

    private void showExportResult() {
        String status = RootShell.getExportStatus();
        if (status.isEmpty()) {
            Toast.makeText(this, "模块尚未返回导出结果，请稍后刷新或重试", Toast.LENGTH_LONG).show();
            return;
        }

        String[] p = status.split("\\|", -1);
        if (p.length > 0 && "OK".equals(p[0])) {
            String dex = p.length > 2 ? p[2] : "0";
            String code = p.length > 3 ? p[3] : "0";
            String dir = p.length > 4 ? p[4] : normalizeExportDir(exportBaseDir) + "/" + selectedPkg + "/";
            String msg = "Dex:" + dex + " CodeItem:" + code + "  " + dir;
            Toast.makeText(this, "导出完成 " + msg, Toast.LENGTH_LONG).show();
            notifyStatus("导出完成", msg);
        } else {
            String msg = p.length > 1 ? p[1] : "导出失败";
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
            notifyStatus("导出失败", msg);
        }
        refresh();
    }

    private void exportLogs() {
        String exportDir = normalizeExportDir(exportBaseDir);
        if (!RootShell.requestLogExport(exportDir)) {
            Toast.makeText(this, "日志导出请求写入失败", Toast.LENGTH_LONG).show();
            return;
        }
        Toast.makeText(this, "日志导出请求已发送", Toast.LENGTH_SHORT).show();
        new Handler().postDelayed(this::showLogExportResult, 2500);
    }

    private void showLogExportResult() {
        String status = RootShell.getLogExportStatus();
        if (status.isEmpty()) {
            Toast.makeText(this, "日志尚未导出完成，请稍后刷新", Toast.LENGTH_LONG).show();
            return;
        }
        String[] p = status.split("\\|", -1);
        String msg = p.length > 1 ? p[1] : status;
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
        notifyStatus("日志导出", msg);
    }

    private void showExportDirDialog() {
        final EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setText(exportBaseDir);
        input.setSelection(input.getText().length());

        new AlertDialog.Builder(this)
            .setTitle("导出目录")
            .setView(input)
            .setPositiveButton("保存", (dialog, which) -> {
                String dir = normalizeExportDir(input.getText().toString());
                exportBaseDir = dir;
                getPreferences(MODE_PRIVATE).edit().putString(KEY_EXPORT_DIR, dir).apply();
                exportDirBtn.setText("导出目录: " + dir);
            })
            .setNegativeButton("取消", null)
            .show();
    }

    private String normalizeExportDir(String dir) {
        if (dir == null) return "/sdcard/FART-LOS21";
        dir = dir.trim();
        if (dir.isEmpty()) return "/sdcard/FART-LOS21";
        while (dir.endsWith("/") && dir.length() > 1) {
            dir = dir.substring(0, dir.length() - 1);
        }
        return dir;
    }

    private void initNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
        NotificationManager nm = (NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "FART 状态", NotificationManager.IMPORTANCE_DEFAULT);
            nm.createNotificationChannel(channel);
        }
    }

    private void notifyStatus(String title, String text) {
        NotificationManager nm = (NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        android.app.Notification n = new android.app.Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(new android.app.Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .build();
        nm.notify(1001, n);
    }

    private int parseInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception e) {
            return 0;
        }
    }

    private int dp(int value) {
        return (int)(value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void saveAllowedPackages() {
        getPreferences(MODE_PRIVATE).edit().putStringSet(KEY_ALLOWED_PACKAGES, new HashSet<>(allowedPackages)).apply();
    }

    private String buildPackagesJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (String pkg : allowedPackages) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeJson(pkg)).append("\"");
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private void pollStatus() {
        refresh();
        handler.postDelayed(this::pollStatus, 3000);
    }
}
