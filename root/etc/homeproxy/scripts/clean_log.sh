#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

set -u

NAME="homeproxy"

log_max_size="50" #KB
main_log_file="/var/run/$NAME/$NAME.log"
meowc_log_file="/var/run/$NAME/meow-c.log"
meows_log_file="/var/run/$NAME/meow-s.log"

while true; do
	sleep 180
	for i in "$main_log_file" "$meowc_log_file" "$meows_log_file"; do
		[ -s "$i" ] || continue
		[ "$(( $(ls -l "$i" | awk -F ' ' '{print $5}') / 1024 >= log_max_size))" -eq "0" ] || echo "" > "$i"
	done
done
