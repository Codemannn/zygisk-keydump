/**
 * KeyDump v6: Debug logging to verify EVP_PKEY_sign interception.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <android/log.h>
#define TAG "KeyDump"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static void* g_handle = NULL;

int EVP_PKEY_sign(void* ctx, unsigned char* sig, size_t* slen,
                  const unsigned char* tbs, size_t tbslen) {
    static int (*real)(void*,unsigned char*,size_t*,const unsigned char*,size_t) = NULL;
    static int calls = 0;
    calls++;
    if (calls == 1) LOGI("EVP_PKEY_sign FIRST CALL! ctx=%p", ctx);
    if (!real) {
        g_handle = dlopen("libcrypto.so", RTLD_NOLOAD|RTLD_NOW);
        LOGI("dlopen libcrypto=%p", g_handle);
        if (g_handle) { real = dlsym(g_handle, "EVP_PKEY_sign"); LOGI("dlsym real=%p", real); }
    }
    if (!real) return -1;
    int ret = real(ctx, sig, slen, tbs, tbslen);
    if (calls == 1 && g_handle) {
        LOGI("real EVP_PKEY_sign returned %d slen=%lu", ret, (unsigned long)*slen);
        void* pk = NULL;
        void** p = (void**)ctx;
        for (int i=4; i<=6; i++) { if (p[i]) { pk = p[i]; LOGI("pkey[%d]=%p", i, pk); } }
        if (pk) {
            int (*i2d)(void*,unsigned char**) = dlsym(g_handle, "i2d_PrivateKey");
            if (i2d) {
                unsigned char* der = NULL;
                int len = i2d(pk, &der);
                LOGI("i2d=%d der=%p", len, der);
                if (len > 0 && der) {
                    FILE* f = fopen("/sdcard/private_key.der", "wb");
                    if (f) { fwrite(der, 1, len, f); fclose(f); LOGI("KEY SAVED %d bytes", len); }
                }
            }
        }
    }
    return ret;
}

__attribute__((constructor)) static void init(void) {
    LOGI("=== KeyDump v6 (debug) loaded ===");
}
