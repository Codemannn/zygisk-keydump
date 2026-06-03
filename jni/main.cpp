/**
 * LD_PRELOAD Hook v4: Intercept EVP_PKEY_sign to capture private key.
 * Injected via ELF patching of libc++_shared.so.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
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
    if (!h) { LOGI("dlopen(%s) failed", lib); return NULL; }
    void* s = dlsym(h, name);
    LOGI("dlsym(%s, %s) = %p", lib, name, s);
    return s;
}

static void save_key(EVP_PKEY* pk) {
    LOGI("save_key called, pk=%p", pk);
    if (!real_i2d) real_i2d = (typeof(real_i2d))fdsym("libcrypto.so", "i2d_PrivateKey");
    if (!real_i2d) { LOGI("i2d_PrivateKey not found"); return; }
    unsigned char* der = NULL;
    int len = real_i2d(pk, &der);
    LOGI("i2d_PrivateKey returned len=%d der=%p", len, der);
    if (len <= 0 || !der) return;
    FILE* f = fopen("/sdcard/private_key.der", "wb");
    if (f) { fwrite(der, 1, len, f); fclose(f); LOGI("DER saved (%d bytes)", len); }
    f = fopen("/sdcard/private_key.hex", "w");
    if (f) {
        for (int i=0; i<len; i++) fprintf(f, "%02x", der[i]);
        fclose(f);
        LOGI("HEX saved");
    }
    saved = 1;
}

extern "C" int EVP_PKEY_sign(EVP_PKEY_CTX* ctx, unsigned char* sig, size_t* slen,
                              const unsigned char* tbs, size_t tbslen) {
    if (!real_sign) {
        real_sign = (typeof(real_sign))fdsym("libcrypto.so", "EVP_PKEY_sign");
        if (!real_sign) return -1;
        LOGI("EVP_PKEY_sign hooked at %p", real_sign);
    }
    if (!saved && ctx) {
        EVP_PKEY* pk = NULL;
        // Try multiple EVP_PKEY_CTX layouts
        void** p = (void**)ctx;
        for (int off=4; off<=6; off++) {
            pk = (EVP_PKEY*)p[off];
            if (pk) {
                LOGI("EVP_PKEY_sign: ctx=%p pkey[%d]=%p", ctx, off, pk);
                save_key(pk);
                break;
            }
        }
    }
    return real_sign(ctx, sig, slen, tbs, tbslen);
}

__attribute__((constructor)) static void init() {
    LOGI("=== KeyDump v4 loaded (ELF patched) ===");
}
