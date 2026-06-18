package com.fartlos21.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import android.util.Log;

public class RootShell {
    private static final String TAG = "FART_CTRL";

    // App's internal files dir, set from MainActivity onCreate
    public static String dataDir = "";

    public static String exec(String cmd) {
        StringBuilder out = new StringBuilder();
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l;
            while ((l = r.readLine()) != null) out.append(l).append("\n");
            r.close();
            p.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "exec exception", e);
        }
        return out.toString().trim();
    }

    /** Write config to app's own data dir; service.sh polls and copies to module dir */
    public static boolean writeConfig(String json) {
        try {
            FileWriter f = new FileWriter(dataDir + "/config.json");
            f.write(json);
            f.close();
            Log.d(TAG, "writeConfig OK to " + dataDir + "/config.json");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "writeConfig failed", e);
            return false;
        }
    }

    /** Check heartbeat file written by service.sh */
    public static boolean isModuleInstalled() {
        boolean ok = new File(dataDir + "/.module_heartbeat").exists();
        Log.d(TAG, "isModuleInstalled=" + ok);
        return ok;
    }

    /** Launch target app via am/monkey (may work without root on some ROMs) */
    public static boolean launchApp(String pkg) {
        exec("am force-stop " + pkg + " 2>/dev/null");
        String r = exec("monkey -p " + pkg + " 1 2>/dev/null");
        return r.contains("Events injected");
    }

    /** Read stats from heartbeat file written by service.sh */
    public static String getStats() {
        String dex = "0", code = "0";
        try {
            BufferedReader r = new BufferedReader(new FileReader(dataDir + "/.stats"));
            String l;
            while ((l = r.readLine()) != null) {
                if (l.startsWith("dex:")) dex = l.substring(4);
                if (l.startsWith("code:")) code = l.substring(5);
            }
            r.close();
        } catch (Exception e) {}
        return dex + "|0|" + code;
    }

    /** Export via service.sh helper — writes a trigger file */
    public static boolean exportDump(String pkg) {
        try {
            FileWriter f = new FileWriter(dataDir + "/.export_trigger");
            f.write(pkg);
            f.close();
            Log.d(TAG, "export trigger written");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "export failed", e);
            return false;
        }
    }
}
