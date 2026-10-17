# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2025 ImmortalWrt.org
#
# HomeProxy — sing-box front-end for routers without LuCI/nftables/ucode
# (e.g. stock Xiaomi/MiWiFi). Backend logic is implemented in Lua and traffic
# steering uses iptables + ipset instead of fw4/nftables.

include $(TOPDIR)/rules.mk

PKG_NAME:=homeproxy
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=ImmortalWrt / community

LUCI_TITLE:=Modern proxy platform (sing-box) for iptables-only routers
PKGARCH:=all

define Package/homeproxy
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=$(LUCI_TITLE)
  PKGARCH:=$(PKGARCH)
  DEPENDS:= \
	+sing-box \
	+lua \
	+libuci-lua \
	+luci-lib-jsonc \
	+iptables \
	+iptables-mod-tproxy \
	+kmod-ipt-tproxy \
	+iptables-mod-ipset \
	+kmod-ipt-ipset \
	+iptables-mod-conntrack \
	+kmod-ipt-conntrack \
	+iptables-mod-multiport \
	+kmod-ipt-multiport \
	+iptables-mod-extra \
	+kmod-ipt-extra \
	+ipset \
	+curl \
	+firewall \
	+uhttpd
endef

define Package/homeproxy/description
  Manages a sing-box client/server with a shell CLI instead of LuCI. Config
  generators and the subscription updater run under the on-device lua
  (luci.json + uci binding); firewall rules are applied with iptables/ipset
  so it works on devices without nftables/fw4/ucode (e.g. MiWiFi).
endef

define Package/homeproxy/conffiles
/etc/config/homeproxy
/etc/homeproxy/resources/direct_list.txt
/etc/homeproxy/resources/proxy_list.txt
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/homeproxy/install
	$(INSTALL_DIR) $(1)
	cp -fpR ./root/* $(1)/
	$(INSTALL_DIR) $(1)/usr/lib/homeproxy $(1)/etc/homeproxy/scripts \
		$(1)/etc/init.d $(1)/etc/homeproxy/web/cgi-bin
	$(INSTALL_BIN) ./root/etc/init.d/homeproxy $(1)/etc/init.d/homeproxy
	$(INSTALL_BIN) ./root/etc/init.d/homeproxy-web $(1)/etc/init.d/homeproxy-web
	$(INSTALL_BIN) ./root/usr/bin/homeproxy $(1)/usr/bin/homeproxy
	$(INSTALL_BIN) ./root/usr/lib/homeproxy/firewall.sh $(1)/usr/lib/homeproxy/firewall.sh
	$(INSTALL_BIN) ./root/usr/lib/homeproxy/firewall_include.sh $(1)/usr/lib/homeproxy/firewall_include.sh
	$(INSTALL_BIN) ./root/etc/homeproxy/scripts/boot_restore.sh $(1)/etc/homeproxy/scripts/boot_restore.sh
	$(INSTALL_BIN) ./root/etc/homeproxy/scripts/clean_log.sh $(1)/etc/homeproxy/scripts/clean_log.sh
	$(INSTALL_BIN) ./root/etc/homeproxy/scripts/update_crond.sh $(1)/etc/homeproxy/scripts/update_crond.sh
	$(INSTALL_BIN) ./root/etc/homeproxy/scripts/update_resources.sh $(1)/etc/homeproxy/scripts/update_resources.sh
	$(INSTALL_BIN) ./root/etc/homeproxy/scripts/guard.sh $(1)/etc/homeproxy/scripts/guard.sh
	$(INSTALL_BIN) ./root/etc/homeproxy/web/cgi-bin/api $(1)/etc/homeproxy/web/cgi-bin/api
	$(INSTALL_DATA) ./root/usr/lib/homeproxy/*.lua $(1)/usr/lib/homeproxy/
	$(INSTALL_BIN) ./root/etc/uci-defaults/homeproxy $(1)/etc/uci-defaults/homeproxy
endef

include $(TOPDIR)/include/package.mk

$(eval $(call BuildPackage,homeproxy))