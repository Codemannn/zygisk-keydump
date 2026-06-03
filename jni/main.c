/**
 * KeyDump: Pure C LD_PRELOAD hook to capture EVP_PKEY.
 * No C++ dependencies, minimal footprint.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <android/log.h>
#define TAG "KeyDump"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int (*real_sign)(void*, unsigned char*, size_t*, const unsigned char*, size_t) = NULL;
static int (*real_i2d)(void*, unsigned char**) = NULL;
static int saved = 0;

static void* fdsym(const char* lib, const char* name) {
    void* h = dlopen(lib, RTLD_NOLOAD|RTLD_NOW);
    if (!h) return NULL;
    return dlsym(h, name);
}

static void save_key(void* pk) {
    if (!real_i2d) real_i2d = (int(*)(void*,unsigned char**))fdsym("libcrypto.so", "i2d_PrivateKey");
    if (!real_i2d) return;
    unsigned char* der = NULL;
    int len = real_i2d(pk, &der);
    LOGI("i2d=%d", len);
    if (len <= 0 || !der) return;
    FILE* f = fopen("/sdcard/private_key.der", "wb");
    if (f) { fwrite(der, 1, len, f); fclose(f); }
    f = fopen("/sdcard/private_key.hex", "w");
    if (f) {
        for (int i=0; i<len; i++) fprintf(f, "%02x", der[i]);
        fclose(f);
    }
    saved = 1;
}

int EVP_PKEY_sign(void* ctx, unsigned char* sig, size_t* slen,
                  const unsigned char* tbs, size_t tbslen) {
    if (!real_sign) real_sign = (int(*)(void*,unsigned char*,size_t*,const unsigned char*,size_t))fdsym("libcrypto.so", "EVP_PKEY_sign");
    if (!real_sign) return -1;
    if (!saved && ctx) {
        void** p = (void**)ctx;
        void* pk = p[5]; /* offset 0x28 */
        if (pk) { LOGI("pkey=%p", pk); save_key(pk); }
    }
    return real_sign(ctx, sig, slen, tbs, tbslen);
}

__attribute__((constructor)) static void init(void) {
    LOGI("=== KeyDump v5 (Pure C) loaded ===");
}
