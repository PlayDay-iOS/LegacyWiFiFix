ARCHS = armv6 armv7 arm64
TARGET = iphone:12.4:3.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LegacyWiFiFix

$(TWEAK_NAME)_FILES = src/Tweak.x
$(TWEAK_NAME)_FRAMEWORKS = CoreFoundation
$(TWEAK_NAME)_LIBRARIES = System

include $(THEOS_MAKE_PATH)/tweak.mk
