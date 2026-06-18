package com.fartlos21.controller;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.view.Gravity;
import android.view.View;
import android.widget.*;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    private TextView statusText, statsText;
    private Button selectBtn, startBtn, exportBtn, refreshBtn;
    private String selectedPkg = "";
    private String selectedName = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        RootShell.dataDir = getFilesDir().getPath();

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
        startBtn.setText("▶ 开始脱壳");
        startBtn.setTextSize(20);
        startBtn.setPadding(0, 20, 0, 20);
        root.addView(startBtn);
        startBtn.setOnClickListener(v -> writeAndLaunch());

        statsText = new TextView(this);
        statsText.setText("Dex: 0  |  CodeItem: 0");
        statsText.setPadding(0, 20, 0, 0);
        root.addView(statsText);

        exportBtn = new Button(this);
        exportBtn.setText("导出到 /sdcard/FART-LOS21/");
        root.addView(exportBtn);
        exportBtn.setOnClickListener(v -> {
            RootShell.exportDump(selectedPkg);
            Toast.makeText(this, "导出请求已发送", Toast.LENGTH_SHORT).show();
        });

        refreshBtn = new Button(this);
        refreshBtn.setText("刷新统计");
        root.addView(refreshBtn);
        refreshBtn.setOnClickListener(v -> refresh());

        setContentView(scroll);
        refresh();
    }

    private void showAppList() {
        List<ApplicationInfo> apps = getPackageManager().getInstalledApplications(0);
        List<String> names = new ArrayList<>();
        List<String> pkgs = new ArrayList<>();

        for (ApplicationInfo ai : apps) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            names.add(getPackageManager().getApplicationLabel(ai).toString());
            pkgs.add(ai.packageName);
        }

        new AlertDialog.Builder(this)
            .setTitle("选择目标应用")
            .setItems(names.toArray(new String[0]), (dialog, which) -> {
                selectedPkg = pkgs.get(which);
                selectedName = names.get(which);
                selectBtn.setText(selectedName);
                refresh();
            })
            .show();
    }

    private void refresh() {
        boolean ok = RootShell.isModuleInstalled();
        statusText.setText("模块状态: " + (ok ? "✓ 已安装" : "✗ 未检测到（需重启后生效）"));
        String s = RootShell.getStats();
        String[] parts = s.split("\\|");
        String dex = (parts.length > 0 ? parts[0] : "0");
        String code = (parts.length > 2 ? parts[2] : "0");
        statsText.setText("Dex: " + dex + "  |  CodeItem: " + code);
    }

    private void writeAndLaunch() {
        if (selectedPkg.isEmpty()) {
            Toast.makeText(this, "请先选择目标应用", Toast.LENGTH_SHORT).show();
            return;
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"enable\":true,");
        json.append("\"packages\":[\"").append(selectedPkg).append("\"],");
        json.append("\"dump_dir\":\"/data/local/tmp/fart_dump\",\"dump_dex\":true,");
        json.append("\"enable_artmethod_hook\":true,\"artmethod_sample_rate\":100,");
        json.append("\"enable_codeitem_dump\":true,\"max_codeitem_dumps\":2000,");
        json.append("\"enable_active_invoke\":true,");
        json.append("\"active_invoke_delay_ms\":1000,\"active_invoke_max_methods\":500,");
        json.append("\"active_invoke_skip_execute\":true,");
        json.append("\"active_invoke_classes\":[]}");

        if (RootShell.writeConfig(json.toString())) {
            Toast.makeText(this, "配置已写入，等待 service.sh 搬运（最长 2 秒）", Toast.LENGTH_LONG).show();
            Toast.makeText(this, "请手动启动 " + selectedName, Toast.LENGTH_SHORT).show();
            new Handler().postDelayed(() -> refresh(), 5000);
        } else {
            Toast.makeText(this, "写入失败", Toast.LENGTH_LONG).show();
        }
    }
}
