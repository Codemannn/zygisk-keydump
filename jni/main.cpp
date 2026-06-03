/**
 * LD_PRELOAD Hook: Intercept EVP_PKEY_sign to capture private key.
 *
 * Compile with NDK:
 *   $NDK/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk APP_ABI=arm64-v8a
 *
 * Deploy:
 *   adb push libs/arm64-v8a/libkeydump.so /data/local/tmp/
 *   adb shell su -c "setprop wrap.com.yzj.kaipanh LD_PRELOAD=/data/local/tmp/libkeydump.so"
 */

#include <dlfcn.h>
#include <stdio.h>
#include <android/log.h>
#define TAG "KeyDump"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

static int (*real_sign)(EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t) = NULL;
static int (*real_i2d)(EVP_PKEY*, unsigned char**) = NULL;
static int saved = 0;

static void* fdsym(const char* lib, const char* name) {
    void* h = dlopen(lib, RTLD_NOLOAD|RTLD_NOW);
    if (!h) return NULL;
    void* s = dlsym(h, name);
    dlclose(h);
    return s;
}

static void save_key(EVP_PKEY* pkey) {
    if (!real_i2d) real_i2d = (typeof(real_i2d))fdsym("libcrypto.so", "i2d_PrivateKey");
    if (!real_i2d) { LOGI("i2d not found"); return; }
    unsigned char* der = NULL;
    int len = real_i2d(pkey, &der);
    LOGI("i2d=%d der=%p", len, der);
    if (len > 0 && der) {
        char p[256]; snprintf(p, sizeof(p), "/sdcard/private_key.der");
        FILE* f = fopen(p, "wb");
        if (f) { fwrite(der, 1, len, f); fclose(f); LOGI("SAVED %s (%d)", p, len); }
        FILE* h = fopen("/sdcard/private_key.hex", "w");
        if (h) { for (int i=0; i<len; i++) fprintf(h, "%02x", der[i]); fclose(h); }
    }
}

extern "C" int EVP_PKEY_sign(EVP_PKEY_CTX* ctx, unsigned char* sig, size_t* slen,
                              const unsigned char* tbs, size_t tbslen) {
    if (!real_sign) real_sign = (typeof(real_sign))fdsym("libcrypto.so", "EVP_PKEY_sign");
    if (!real_sign) return -1;
    if (!saved && ctx) {
        void** p = (void**)ctx;
        EVP_PKEY* pk = (EVP_PKEY*)p[5];
        LOGI("SIGN ctx=%p pkey=%p", ctx, pk);
        if (pk) { save_key(pk); saved = 1; }
    }
    return real_sign(ctx, sig, slen, tbs, tbslen);
}

__attribute__((constructor)) static void init() {
    LOGI("=== KeyDump loaded ===");
}
