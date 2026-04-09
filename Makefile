ARCHS = armv7 arm64
TARGET = iphone:10.3:10.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WiFiFixOldiOS

WiFiFixOldiOS_FILES = src/Tweak.x
WiFiFixOldiOS_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
