ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:11.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FckZck

FckZck_FILES = Tweak.xm
FckZck_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
