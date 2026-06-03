LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := keydump
LOCAL_SRC_FILES := main.c
LOCAL_LDLIBS    := -llog -ldl
LOCAL_CFLAGS    := -O2 -fvisibility=hidden -fPIC
include $(BUILD_SHARED_LIBRARY)
