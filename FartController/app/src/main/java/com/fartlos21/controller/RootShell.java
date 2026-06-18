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

    public static boolean writeLocalStatus(String status) {
        try {
            FileWriter f = new FileWriter(dataDir + "/.dump_status");
            f.write(status);
            f.close();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "writeLocalStatus failed", e);
            return false;
        }
    }

    public static boolean writeAutoExport(String pkg, String exportDir) {
        try {
            FileWriter f = new FileWriter(dataDir + "/.auto_export");
            f.write(pkg + "|" + exportDir);
            f.close();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "writeAutoExport failed", e);
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

    /** Write launch trigger for service.sh (root) to execute */
    public static boolean writeLaunchTrigger(String pkg) {
        try {
            FileWriter f = new FileWriter(dataDir + "/.launch_trigger");
            f.write(pkg);
            f.close();
            Log.d(TAG, "launch trigger written for " + pkg);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "launch trigger failed", e);
            return false;
        }
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

    public static String getDumpStatus() {
        try {
            BufferedReader r = new BufferedReader(new FileReader(dataDir + "/.dump_status"));
            String l = r.readLine();
            r.close();
            return l == null ? "" : l;
        } catch (Exception e) {
            return "";
        }
    }

    /** Export via service.sh helper — writes a trigger file */
    public static boolean exportDump(String pkg, String exportDir) {
        try {
            new File(dataDir + "/.export_status").delete();
            FileWriter f = new FileWriter(dataDir + "/.export_trigger");
            f.write(pkg + "|" + exportDir);
            f.close();
            Log.d(TAG, "export trigger written");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "export failed", e);
            return false;
        }
    }

    public static String getExportStatus() {
        try {
            BufferedReader r = new BufferedReader(new FileReader(dataDir + "/.export_status"));
            String l = r.readLine();
            r.close();
            return l == null ? "" : l;
        } catch (Exception e) {
            return "";
        }
    }

    public static boolean requestLogExport(String exportDir) {
        try {
            new File(dataDir + "/.log_export_status").delete();
            FileWriter f = new FileWriter(dataDir + "/.log_export_trigger");
            f.write(exportDir);
            f.close();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "requestLogExport failed", e);
            return false;
        }
    }

    public static String getLogExportStatus() {
        try {
            BufferedReader r = new BufferedReader(new FileReader(dataDir + "/.log_export_status"));
            String l = r.readLine();
            r.close();
            return l == null ? "" : l;
        } catch (Exception e) {
            return "";
        }
    }
}
