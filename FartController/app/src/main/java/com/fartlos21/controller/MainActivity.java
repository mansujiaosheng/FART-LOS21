package com.fartlos21.controller;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
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
    private Spinner modeSpinner;
    private EditText classInput, maxMethodsInput, delayInput;
    private CheckBox skipExecBox;
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
        title.setText("FART\u63a7\u5236\u5668");
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Status
        statusText = new TextView(this);
        statusText.setText("\u6a21\u5757: ...");
        root.addView(statusText);

        // Refresh button
        Button refreshBtn = new Button(this);
        refreshBtn.setText("\u5237\u65b0");
        root.addView(refreshBtn);
        refreshBtn.setOnClickListener(v -> refresh());

        // App selection
        Button selectBtn = new Button(this);
        selectBtn.setText("\u9009\u62e9\u5e94\u7528");
        root.addView(selectBtn);
        selectBtn.setOnClickListener(v -> showAppList());

        final TextView selectedLabel = new TextView(this);
        selectedLabel.setText("\u672a\u9009\u62e9");
        root.addView(selectedLabel);

        // Mode spinner
        modeSpinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item,
                new String[]{"Dex Only", "CodeItem", "Active Invoke"});
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        modeSpinner.setAdapter(adapter);
        root.addView(modeSpinner);

        // Active invoke config
        classInput = new EditText(this);
        classInput.setHint("\u7c7b\u540d\uff08\u6bcf\u884c\u4e00\u4e2a\uff09");
        classInput.setLines(3);
        root.addView(classInput);

        maxMethodsInput = new EditText(this);
        maxMethodsInput.setText("200");
        root.addView(maxMethodsInput);

        delayInput = new EditText(this);
        delayInput.setText("3000");
        root.addView(delayInput);

        skipExecBox = new CheckBox(this);
        skipExecBox.setText("\u8df3\u8fc7\u6267\u884c");
        skipExecBox.setChecked(true);
        root.addView(skipExecBox);

        // Write & Launch
        Button writeBtn = new Button(this);
        writeBtn.setText("\u5199\u5165\u5e76\u542f\u52a8");
        writeBtn.setTextSize(18);
        root.addView(writeBtn);
        writeBtn.setOnClickListener(v -> writeAndLaunch());

        // Stats
        statsText = new TextView(this);
        root.addView(statsText);

        // Export
        Button exportBtn = new Button(this);
        exportBtn.setText("\u5bfc\u51fa\u5230 /sdcard");
        root.addView(exportBtn);
        exportBtn.setOnClickListener(v -> {
            RootShell.exportDump(selectedPkg);
            Toast.makeText(this, "\u5bfc\u51fa\u5b8c\u6210", Toast.LENGTH_SHORT).show();
        });

        setContentView(scroll);
        refresh();
    }

    private void showAppList() {
        List<ApplicationInfo> apps = getPackageManager().getInstalledApplications(0);
        List<String> names = new ArrayList<>();
        List<String> pkgs = new ArrayList<>();

        for (ApplicationInfo ai : apps) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            String name = getPackageManager().getApplicationLabel(ai).toString();
            names.add(name);
            pkgs.add(ai.packageName);
        }

        new AlertDialog.Builder(this)
            .setTitle("\u9009\u62e9\u76ee\u6807")
            .setItems(names.toArray(new String[0]), (dialog, which) -> {
                selectedPkg = pkgs.get(which);
                selectedName = names.get(which);
                refresh();
            })
            .show();
    }

    private void refresh() {
        boolean ok = RootShell.isModuleInstalled();
        statusText.setText("\u6a21\u5757: " + (ok ? "\u2713 \u5df2\u5b89\u88c5" : "\u2717 \u672a\u627e\u5230") + "  " + selectedName);
        String s = RootShell.getStats();
        String[] parts = s.split("\\|");
        statsText.setText("Dex: " + (parts.length > 0 ? parts[0] : "0")
            + "  JSON: " + (parts.length > 1 ? parts[1] : "0")
            + "  Code: " + (parts.length > 2 ? parts[2] : "0"));
    }

    private void writeAndLaunch() {
        if (selectedPkg.isEmpty()) {
            Toast.makeText(this, "\u8bf7\u5148\u9009\u62e9\u5e94\u7528", Toast.LENGTH_SHORT).show();
            return;
        }

        int mode = modeSpinner.getSelectedItemPosition();
        StringBuilder json = new StringBuilder();
        json.append("{\"enable\":true,");
        json.append("\"packages\":[\"").append(selectedPkg).append("\"],");
        json.append("\"dump_dir\":\"/data/local/tmp/fart\",\"dump_dex\":true,");

        switch (mode) {
            case 0:
                json.append("\"enable_artmethod_hook\":false,\"enable_codeitem_dump\":false,\"enable_active_invoke\":false}");
                break;
            case 1:
                json.append("\"enable_artmethod_hook\":true,\"artmethod_sample_rate\":100,");
                json.append("\"enable_codeitem_dump\":true,\"max_codeitem_dumps\":500,\"enable_active_invoke\":false}");
                break;
            case 2: {
                String cls = classInput.getText().toString().trim();
                json.append("\"enable_artmethod_hook\":true,\"artmethod_sample_rate\":1,");
                json.append("\"enable_codeitem_dump\":true,\"max_codeitem_dumps\":500,\"enable_active_invoke\":true,");
                json.append("\"active_invoke_delay_ms\":").append(delayInput.getText()).append(",");
                json.append("\"active_invoke_max_methods\":").append(maxMethodsInput.getText()).append(",");
                json.append("\"active_invoke_skip_execute\":").append(skipExecBox.isChecked());
                if (cls.isEmpty()) {
                    json.append(",\"active_invoke_classes\":[]}");
                } else {
                    json.append(",\"active_invoke_classes\":[\"").append(cls.replace("\n", "\",\"")).append("\"]}");
                }
                break;
            }
        }

        if (RootShell.writeConfig(json.toString())) {
            Toast.makeText(this, "\u914d\u7f6e\u5df2\u5199\u5165", Toast.LENGTH_SHORT).show();
            RootShell.launchApp(selectedPkg);
            new Handler().postDelayed(() -> refresh(), 5000);
        } else {
            Toast.makeText(this, "\u5199\u5165\u5931\u8d25", Toast.LENGTH_LONG).show();
        }
    }
}
