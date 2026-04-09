ARCHS = armv7 arm64
TARGET = iphone:12.4:9.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WiFiFixOldiOS

WiFiFixOldiOS_FILES = src/Tweak.x
WiFiFixOldiOS_FRAMEWORKS = CoreFoundation
WiFiFixOldiOS_LIBRARIES = System

include $(THEOS_MAKE_PATH)/tweak.mk
