package com.fartlos21.controller;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    private TextView statusText, statsText;
    private Button selectBtn, startBtn, exportBtn;
    private String selectedPkg = "";
    private String selectedName = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(40, 40, 40, 40);
        scroll.addView(root);

        // Title
        TextView title = new TextView(this);
        title.setText("FART-LOS21 脱壳工具");
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Status
        statusText = new TextView(this);
        statusText.setText("模块状态: 检测中...");
        statusText.setTextSize(14);
        root.addView(statusText);

        // App selection row
        LinearLayout appRow = new LinearLayout(this);
        appRow.setOrientation(LinearLayout.HORIZONTAL);
        selectBtn = new Button(this);
        selectBtn.setText("选择目标应用");
        selectBtn.setTextSize(14);
        appRow.addView(selectBtn);
        final TextView pkgLabel = new TextView(this);
        pkgLabel.setText("（未选择）");
        pkgLabel.setPadding(20, 0, 0, 0);
        pkgLabel.setGravity(Gravity.CENTER_VERTICAL);
        appRow.addView(pkgLabel);
        root.addView(appRow);

        selectBtn.setOnClickListener(v -> showAppList());

        // Info box
        LinearLayout infoBox = new LinearLayout(this);
        infoBox.setOrientation(LinearLayout.VERTICAL);
        infoBox.setPadding(20, 20, 20, 20);
        infoBox.setBackgroundColor(0x22FFFFFF);
        root.addView(infoBox);

        String[] infos = {
            "✓ 拦截 DefineClass 实时 dump DEX",
            "✓ Hook ArtMethod::Invoke 捕获 CodeItem",
            "✓ 主动调用目标方法触发加壳方法解密",
            "✓ 自动采样 + 去重，无需额外配置"
        };
        for (String s : infos) {
            TextView tv = new TextView(this);
            tv.setText(s);
            tv.setTextSize(13);
            infoBox.addView(tv);
        }

        // Start button
        startBtn = new Button(this);
        startBtn.setText("▶ 开始脱壳");
        startBtn.setTextSize(20);
        startBtn.setPadding(0, 20, 0, 20);
        root.addView(startBtn);
        startBtn.setOnClickListener(v -> writeAndLaunch());

        // Stats
        statsText = new TextView(this);
        statsText.setText("Dex: 0  |  CodeItem: 0");
        statsText.setPadding(0, 20, 0, 0);
        root.addView(statsText);

        // Export
        exportBtn = new Button(this);
        exportBtn.setText("导出到 /sdcard/FART-LOS21/");
        root.addView(exportBtn);
        exportBtn.setOnClickListener(v -> {
            RootShell.exportDump(selectedPkg);
            Toast.makeText(this, "导出完成", Toast.LENGTH_SHORT).show();
        });

        // Refresh button
        Button refreshBtn = new Button(this);
        refreshBtn.setText("刷新统计");
        root.addView(refreshBtn);
        refreshBtn.setOnClickListener(v -> refresh());

        // Settings button
        Button settingsBtn = new Button(this);
        settingsBtn.setText("⚙ Root 设置");
        settingsBtn.setTextSize(12);
        settingsBtn.setGravity(Gravity.CENTER);
        root.addView(settingsBtn);
        settingsBtn.setOnClickListener(v -> showSettings());

        setContentView(scroll);
        loadSuCmd();
        refresh();
    }

    private void loadSuCmd() {
        SharedPreferences prefs = getPreferences(MODE_PRIVATE);
        RootShell.suCmd = prefs.getString("su_cmd", "kp -c");
    }

    private void showSettings() {
        final String[] presets = {"kp -c", "su -c", "su -c", "tsu"};
        final String[] labels = {"APatch (kp -c)", "Magisk (su -c)", "SuperSU (su -c)", "Termux (tsu)"};
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(40, 20, 40, 20);

        TextView hint = new TextView(this);
        hint.setText("选择 Root 命令：");
        hint.setTextSize(14);
        layout.addView(hint);

        final RadioGroup rg = new RadioGroup(this);
        rg.setOrientation(RadioGroup.VERTICAL);
        int checkedId = -1;
        for (int i = 0; i < presets.length; i++) {
            RadioButton rb = new RadioButton(this);
            rb.setText(labels[i]);
            rb.setId(i);
            rg.addView(rb);
            if (RootShell.suCmd.equals(presets[i])) checkedId = i;
        }
        // Custom radio
        final RadioButton customRb = new RadioButton(this);
        customRb.setText("自定义");
        customRb.setId(99);
        rg.addView(customRb);
        if (checkedId == -1) {
            customRb.setChecked(true);
            checkedId = 99;
        } else {
            rg.check(checkedId);
        }
        layout.addView(rg);

        final EditText customInput = new EditText(this);
        customInput.setHint("例如: su -c");
        customInput.setInputType(InputType.TYPE_CLASS_TEXT);
        if (checkedId == -1) {
            customInput.setText(RootShell.suCmd);
            customInput.setVisibility(View.VISIBLE);
        } else {
            customInput.setVisibility(View.GONE);
        }
        layout.addView(customInput);

        rg.setOnCheckedChangeListener((group, id) -> {
            customInput.setVisibility(id == 99 ? View.VISIBLE : View.GONE);
        });

        new AlertDialog.Builder(this)
            .setTitle("Root 设置")
            .setView(layout)
            .setPositiveButton("确定", (dialog, which) -> {
                String cmd;
                if (customRb.isChecked()) {
                    cmd = customInput.getText().toString().trim();
                    if (cmd.isEmpty()) cmd = "kp -c";
                } else {
                    int id = rg.getCheckedRadioButtonId();
                    cmd = presets[id];
                }
                RootShell.suCmd = cmd;
                SharedPreferences prefs = getPreferences(MODE_PRIVATE);
                prefs.edit().putString("su_cmd", cmd).apply();
                Toast.makeText(this, "Root 命令已设为: " + cmd, Toast.LENGTH_SHORT).show();
                refresh();
            })
            .setNegativeButton("取消", null)
            .show();
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
        statusText.setText("模块状态: " + (ok ? "✓ 已安装" : "✗ 未找到"));
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

        // Full config: enable everything for second-gen extraction shells
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
            Toast.makeText(this, "配置已写入，正在启动 " + selectedName, Toast.LENGTH_SHORT).show();
            RootShell.launchApp(selectedPkg);
            new Handler().postDelayed(() -> refresh(), 5000);
        } else {
            Toast.makeText(this, "写入失败，请检查模块是否安装", Toast.LENGTH_LONG).show();
        }
    }
}
