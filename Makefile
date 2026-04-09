ARCHS = armv7
TARGET = iphone:10.3:10.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WiFiFixOldiOS

WiFiFixOldiOS_FILES = src/Tweak.x
WiFiFixOldiOS_FRAMEWORKS = CoreFoundation
WiFiFixOldiOS_LIBRARIES = System

include $(THEOS_MAKE_PATH)/tweak.mk
