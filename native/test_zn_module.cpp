// test_zn_module.cpp – Incremental: load config + check allowlist + dlopen
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>
#include "zygisk.hpp"

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static const char *kHookLib = "/data/local/tmp/fart/libfart-hook.so";

static char *readFile(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return nullptr;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return nullptr; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)(len + 1));
    if (!buf) { fclose(f); return nullptr; }
    size_t n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[n] = 0;
    return buf;
}

static bool jsonEnabled(const char *json) {
    const char *p = strstr(json, "\"enable\"");
    if (!p) return false;
    p = strchr(p, ':'); if (!p) return false;
    p++; while (*p == ' ' || *p == '\t') p++;
    return (strncmp(p, "true", 4) == 0);
}

class TestModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("onLoad pid=%d", getpid());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        LOGI("preAppSpecialize pid=%d", getpid());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize pid=%d", getpid());

        // Read config
        char *json = readFile("/data/local/tmp/fart/config.json");
        if (!json) { LOGW("no config"); return; }
        LOGI("config loaded: %s", json);
        bool ok = jsonEnabled(json);
        free(json);
        if (!ok) { LOGI("disabled"); return; }
        LOGI("enabled=true, loading hook...");

        // dlopen
        if (access(kHookLib, R_OK) != 0) { LOGE("hook not found"); return; }
        void *h = dlopen(kHookLib, RTLD_NOW);
        if (h) LOGI("dlopen OK");
        else LOGE("dlopen: %s", dlerror());
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override { LOGI("preServer"); }
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override { LOGI("postServer"); }
};

REGISTER_ZYGISK_MODULE(TestModule)
