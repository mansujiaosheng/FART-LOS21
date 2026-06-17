// zygisk.hpp – Zygisk API header (no lambdas, static thunks, minimal size)
#pragma once
#include <jni.h>
#include <stddef.h>

namespace zygisk {

struct Api { void *vt; int api_version; };

struct AppSpecializeArgs {
    jint &uid; jint &gid; jintArray &gids; jint &runtime_flags;
    jobjectArray &rlimits; jint &mount_external; jstring &se_info;
    jstring &nice_name; jstring &instruction_set; jstring &app_data_dir;
    jintArray *const fds_to_ignore;
    jboolean *const is_child_zygote; jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs; jboolean *const mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint &uid; jint &gid; jintArray &gids; jint &runtime_flags;
    jlong &permitted_capabilities; jlong &effective_capabilities;
};

class ModuleBase {
public:
    virtual ~ModuleBase() = default;
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

namespace internal {

struct module_abi {
    long api_version;
    ModuleBase *impl;
    void (*preAppSpecialize)(ModuleBase *, AppSpecializeArgs *);
    void (*postAppSpecialize)(ModuleBase *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(ModuleBase *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(ModuleBase *, const ServerSpecializeArgs *);
};

struct api_table {
    void *impl;
    bool (*registerModule)(api_table *, module_abi *);
    void *reserved[8];
};

} // namespace internal

} // namespace zygisk

// Macro: static thunks, no lambdas, no C++ runtime dependencies
#define REGISTER_ZYGISK_MODULE(CLAZZ)                                          \
    namespace {                                                                \
    static void _t_onL(void *m, zygisk::Api *a, JNIEnv *e) { ((CLAZZ*)m)->onLoad(a, e); } \
    static void _t_preA(void *m, zygisk::AppSpecializeArgs *a) { ((CLAZZ*)m)->preAppSpecialize(a); } \
    static void _t_postA(void *m, const zygisk::AppSpecializeArgs *a) { ((CLAZZ*)m)->postAppSpecialize(a); } \
    static void _t_preS(void *m, zygisk::ServerSpecializeArgs *a) { ((CLAZZ*)m)->preServerSpecialize(a); } \
    static void _t_postS(void *m, const zygisk::ServerSpecializeArgs *a) { ((CLAZZ*)m)->postServerSpecialize(a); } \
    }                                                                          \
    extern "C" __attribute__((visibility("default")))                           \
    void zygisk_module_entry(zygisk::internal::api_table *table, JNIEnv *env) {\
        static CLAZZ module;                                                    \
        static zygisk::internal::module_abi abi;                                \
        abi.api_version = 4;                                                    \
        abi.impl = &module;                                                     \
        abi.preAppSpecialize = (void (*)(zygisk::ModuleBase *, zygisk::AppSpecializeArgs *))_t_preA; \
        abi.postAppSpecialize = (void (*)(zygisk::ModuleBase *, const zygisk::AppSpecializeArgs *))_t_postA; \
        abi.preServerSpecialize = (void (*)(zygisk::ModuleBase *, zygisk::ServerSpecializeArgs *))_t_preS; \
        abi.postServerSpecialize = (void (*)(zygisk::ModuleBase *, const zygisk::ServerSpecializeArgs *))_t_postS; \
        if (table && table->registerModule)                                     \
            table->registerModule(table, &abi);                                 \
        module.onLoad(nullptr, env);                                            \
    }
