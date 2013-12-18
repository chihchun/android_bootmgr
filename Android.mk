
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE        := bootmgr
LOCAL_MODULE_TAGS   := optional
LOCAL_C_INCLUDES    := $(LOCAL_PATH)
LOCAL_SRC_FILES     := bootmgr.c
LOCAL_FORCE_STATIC_EXECUTABLE   := true
LOCAL_STATIC_LIBRARIES          := libc
include $(BUILD_EXECUTABLE)
