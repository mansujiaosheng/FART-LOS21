// zygisk_loader.cpp – FART Zygisk loader (基于已验证的测试模块结构)
// 官方 header + static libc++，实现中无 std::string，只有 char 数组
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>
#include <jni.h>
#include "zygisk.hpp"

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static const char* kHookLib = "/data/local/tmp/fart/libfart-hook.so";
static const char* kConfigPath = "/data/local/tmp/fart/config.json";

static char* readFile(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return nullptr;
    fseek(f, 0, SEEK_END); long len = ftell(f);
    if (len <= 0) { fclose(f); return nullptr; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc((size_t)(len + 1));
    if (!buf) { fclose(f); return nullptr; }
    size_t n = fread(buf, 1, (size_t)len, f);
    fclose(f); buf[n] = 0; return buf;
}

static bool inArray(const char *json, const char *key, const char *val) {
    if (!json || !key || !val) return false;
    char sk[128]; snprintf(sk, sizeof(sk), "\"%s\"", key);
    const char *p = strstr(json, sk); if (!p) return false;
    p = strchr(p, '['); if (!p) return false; p++;
    while (*p && *p != ']') {
        const char *q = strchr(p, '"'); if (!q) break; q++;
        const char *r = strchr(q, '"'); if (!r) break;
        size_t vl = (size_t)(r - q);
        if (vl == strlen(val) && strncmp(q, val, vl) == 0) return true;
        p = r + 1;
    }
    return false;
}

class FartLoader : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("onLoad pid=%d", getpid());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        LOGI("preAppSpecialize pid=%d", getpid());
        // 不读包名，在 postAppSpecialize 中统一处理
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize pid=%d", getpid());

        // Get package name
        char pkg[256] = {};
        bool got = false;
        if (args) {
            typedef jint (*GV_t)(JavaVM**,jsize,jsize*);
            GV_t gv = (GV_t)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
            if (gv) {
                JavaVM *vm = nullptr;
                jsize nVMs = 0;
                if (gv(&vm, 1, &nVMs) == JNI_OK && nVMs > 0 && vm) {
                    JNIEnv *env = nullptr;
                    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK && env) {
                        const char *chars = env->GetStringUTFChars(args->nice_name, nullptr);
                        if (chars) {
                            strncpy(pkg, chars, sizeof(pkg)-1);
                            env->ReleaseStringUTFChars(args->nice_name, chars);
                            got = true;
                        }
                    }
                }
            }
        }
        if (!got) {
            int fd = open("/proc/self/cmdline", O_RDONLY);
            if (fd >= 0) { ssize_t n = read(fd, pkg, sizeof(pkg)-1); close(fd); if(n>0) pkg[n]=0; }
        }
        if (pkg[0]==0) return;
        LOGI("pkg=%s", pkg);

        // Hard allowlist check (only these packages)
        static const char* allow[] = {"infosecadventures.allsafe","com.funshion.video.mobile","com.example.farttest","com.farttest.secret2x",nullptr};
        bool hit = false;
        for (int i=0; allow[i]; i++) { if (strcmp(pkg, allow[i])==0) { hit=true; break; }}
        if (!hit) { LOGI("not in hard allowlist"); return; }

        // Load hook lib
        if (access(kHookLib, R_OK) != 0) { LOGE("hook not found"); return; }
        void *h = dlopen(kHookLib, RTLD_NOW);
        if (!h) { LOGE("dlopen: %s", dlerror()); return; }
        LOGI("✅ dlopen OK");

        // Call fart_on_app_specialize
        typedef jint (*GV_t)(JavaVM**,jsize,jsize*);
        GV_t gv2 = (GV_t)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
        JNIEnv* env_local = nullptr;
        if (gv2) { JavaVM *vm=nullptr; jsize n=0; if(gv2(&vm,1,&n)==JNI_OK&&n>0&&vm) vm->GetEnv((void**)&env_local, JNI_VERSION_1_6); }
        typedef void (*FartInit_t)(JNIEnv*, const char*, const char*);
        FartInit_t init = (FartInit_t)dlsym(h, "fart_on_app_specialize");
        if (init) { LOGI("✅ calling init"); init(env_local, pkg, "/data/adb/modules/fart-los21"); }
        else LOGW("no init symbol");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {}
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override {}
};

REGISTER_ZYGISK_MODULE(FartLoader)
