package com.fartlos21.controller;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileWriter;

public class RootShell {
    // Customizable su command template: %s is replaced with the actual command
    public static String suCmd = "kp -c";

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
            out.append("ERR:").append(e.getMessage());
        }
        return out.toString().trim();
    }

    public static String su(String cmd) {
        return exec(suCmd + " '" + cmd.replace("'", "'\\''") + "'");
    }

    public static boolean isModuleInstalled() {
        return !su("ls /data/adb/modules/fart-los21/ 2>/dev/null || echo N").contains("N");
    }

    public static boolean writeConfig(String json, String tmpDir) {
        try {
            FileWriter f = new FileWriter(tmpDir + "/fart_config.json");
            f.write(json);
            f.close();
            String r = su("cp " + tmpDir + "/fart_config.json /data/adb/modules/fart-los21/config/config.json && chmod 644 /data/adb/modules/fart-los21/config/config.json && echo Y || echo N");
            new File(tmpDir + "/fart_config.json").delete();
            return r.contains("Y");
        } catch (Exception e) {
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
