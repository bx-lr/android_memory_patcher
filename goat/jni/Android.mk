LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := goat
LOCAL_SRC_FILES := goat.c

include $(BUILD_EXECUTABLE)
