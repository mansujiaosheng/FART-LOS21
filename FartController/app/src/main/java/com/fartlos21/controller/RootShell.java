package com.fartlos21.controller;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileWriter;
import android.util.Log;

public class RootShell {
    private static final String TAG = "FART_CTRL";

    // Customizable su command (use full path — app process PATH may differ)
    public static String suCmd = "/system/bin/kp -c";

    public static String exec(String cmd) {
        StringBuilder out = new StringBuilder();
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l;
            while ((l = r.readLine()) != null) out.append(l).append("\n");
            r.close();
            BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            StringBuilder err = new StringBuilder();
            while ((l = er.readLine()) != null) err.append(l).append("\n");
            er.close();
            p.waitFor();
            int exit = p.exitValue();
            if (exit != 0 || err.length() > 0) {
                Log.w(TAG, "exec exit=" + exit + " stderr=[" + err.toString().trim()
                    + "] cmd=[" + cmd.substring(0, Math.min(cmd.length(), 200)) + "]");
            }
        } catch (Exception e) {
            Log.e(TAG, "exec exception", e);
            out.append("ERR:").append(e.getMessage());
        }
        return out.toString().trim();
    }

    public static String su(String cmd) {
        String full = suCmd + " '" + cmd.replace("'", "'\\''") + "'";
        Log.d(TAG, "su cmd=" + full.substring(0, Math.min(full.length(), 300)));
        String r = exec(full);
        Log.d(TAG, "su result=[" + r + "]");
        return r;
    }

    public static boolean isModuleInstalled() {
        String r = su("ls /data/adb/modules/fart-los21/ 2>/dev/null || echo N");
        boolean ok = !r.contains("N");
        Log.d(TAG, "isModuleInstalled=" + ok);
        return ok;
    }

    public static boolean writeConfig(String json) {
        try {
            byte[] data = json.getBytes("UTF-8");
            String b64 = android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP);
            Log.d(TAG, "writeConfig json=" + json.substring(0, Math.min(json.length(), 200)));
            Log.d(TAG, "writeConfig b64=" + b64);
            String cmd = "echo '" + b64 + "' | base64 -d > /data/adb/modules/fart-los21/config/config.json && chmod 644 /data/adb/modules/fart-los21/config/config.json && echo Y || echo N";
            String r = su(cmd);
            Log.d(TAG, "writeConfig result=[" + r + "]");
            return r.contains("Y");
        } catch (Exception e) {
            Log.e(TAG, "writeConfig exception", e);
            return false;
        }
    }

    public static boolean launchApp(String pkg) {
        String r = su("am force-stop " + pkg + " 2>/dev/null; monkey -p " + pkg + " 1 2>/dev/null || am start -n " + pkg + "/.MainActivity 2>/dev/null; echo OK");
        return r.contains("OK");
    }

    public static String getStats() {
        String d = su("ls /data/local/tmp/fart_dump/*.dex 2>/dev/null | wc -l || echo 0");
        String c = su("ls /data/local/tmp/fart_dump/methods/*.code 2>/dev/null | wc -l || echo 0");
        return d.trim() + "|0|" + c.trim();
    }

    public static boolean exportDump(String pkg) {
        String dir = "/sdcard/FART-LOS21/" + pkg + "/";
        su("mkdir -p " + dir + "methods");
        su("cp /data/local/tmp/fart_dump/*.dex " + dir + " 2>/dev/null");
        su("cp /data/local/tmp/fart_dump/methods/* " + dir + "methods/ 2>/dev/null");
        su("chmod -R 644 " + dir + "* 2>/dev/null");
        return true;
    }
}
