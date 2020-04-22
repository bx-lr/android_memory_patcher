LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := patch
LOCAL_SRC_FILES := patch.c include/inih_r22/ini.c parser.c poll.c myptrace.c resolve.c include/libb64-1.2/src/cdecode.c hooker.c

include $(BUILD_EXECUTABLE)
