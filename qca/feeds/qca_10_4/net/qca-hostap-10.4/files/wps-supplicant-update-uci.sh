#!/bin/sh
#
# Copyright (c) 2017 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

#
# Copyright (c) 2014, The Linux Foundation. All rights reserved.
#
#  Permission to use, copy, modify, and/or distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.
#
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

IFNAME=$1
CMD=$2
. /sbin/wifi detect

parent=$(cat /sys/class/net/${IFNAME}/parent)

is_section_ifname() {
	local config=$1
	local ifname
	config_get ifname "$config" ifname
	[ "${ifname}" = "$2" ] && eval "$3=$config"
}

get_psk() {
	local count=
	local conf=$1
	local index=
	# This finds the last PSK in the supplicant config and strips off leading
	# and trailing quotes (if it has them). Generally the quotes are not there
	# when doing WPS push button.
	psk=$(awk 'BEGIN{FS="="} /psk=/ {print $0}' $conf |grep "psk=" |tail -n 1 | cut -f 2 -d= | sed -e 's/^"\(.*\)"/\1/')
}

wps_pbc_enhc_get_clone_config() {
	if [ -r $wps_pbc_enhc_file ]; then
		local overwrite_ap_all=$(awk "/\-:overwrite_ap_settings_all/ {print;exit}" $wps_pbc_enhc_file | sed "s/\-://")
		local overwrite_sta_all=$(awk "/\-:overwrite_sta_settings_all/ {print;exit}" $wps_pbc_enhc_file | sed "s/\-://")
		local overwrite_ap=$(awk "/$parent:overwrite_ap_settings/ {print;exit}" $wps_pbc_enhc_file | sed "s/$parent://")

		[ -n "$overwrite_ap_all" ] && \
			IFNAME_OVERWRITE_AP=$(awk "/:[0-9\-]*:[0-9\-]*:.*:clone/" $wps_pbc_enhc_file | cut -f1 -d:)

		[ -n "$overwrite_sta_all" ] && \
			IFNAME_OVERWRITE_STA=$(awk "/:[0-9\-]*:[0-9\-]*:.*:clone/" $wps_pbc_enhc_file | cut -f1 -d:)

		[ -z "$overwrite_ap_all" -a -n "$overwrite_ap" ] && \
			IFNAME_OVERWRITE_AP=$(awk "/:[0-9\-]*:[0-9\-]*:$parent:clone/" $wps_pbc_enhc_file | cut -f1 -d:)
	fi
}

wps_pbc_enhc_overwrite_ap_settings() {
	local ifname_overwrite=$1
	local ssid_overwrite=$2
	local auth_overwrite=$3
	local encr_overwrite=$4
	local key_overwrite=
	local parent_overwrite=$(cat /sys/class/net/${ifname_overwrite}/parent)
	local ssid_suffix=$(awk "/\-:overwrite_ssid_suffix:/ {print;exit}" $wps_pbc_enhc_file | \
						sed "s/\-:overwrite_ssid_suffix://")
	local ssid_band_suffix=$(awk "/$parent_overwrite:overwrite_ssid_band_suffix:/ {print;exit}" $wps_pbc_enhc_file | \
						sed "s/$parent_overwrite:overwrite_ssid_band_suffix://")

	[ "${auth_overwrite}" = "WPA2PSK" -o "${auth_overwrite}" = "WPAPSK" ] && key_overwrite=$5

	if [ -r /var/run/hostapd-${parent_overwrite}/${ifname_overwrite} ]; then
		hostapd_cli -i${ifname_overwrite} -p/var/run/hostapd-${parent_overwrite} wps_config \
			${ssid_overwrite}${ssid_suffix}${ssid_band_suffix} ${auth_overwrite} ${encr_overwrite} ${key_overwrite}
	fi
}

wps_pbc_enhc_overwrite_sta_settings() {
	local ifname_overwrite=$1
	local ssid_overwrite=$2
	local auth_overwrite=$3
	local key_overwrite=
	local key_overwrite_len=
	local nw=
	local sect=
	config_foreach is_section_ifname wifi-iface $ifname_overwrite sect

	[ "${auth_overwrite}" = "WPA2-PSK" -o "${auth_overwrite}" = "WPA-PSK" ] && {
		key_overwrite=$4
		key_overwrite_len=${#key_overwrite}
	}

	if [ -r /var/run/wpa_supplicant-${ifname_overwrite} ]; then
		nw=`wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} add_network | cut -d ' ' -f 4`
		wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw ssid \"${ssid_overwrite}\"
		uci set wireless.${sect}.ssid="$ssid_overwrite"
		case $auth_overwrite in
			WPA2-PSK)
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw key_mgmt WPA-PSK
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw auth_alg OPEN
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw pairwise CCMP
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw proto RSN
				if [ $key_overwrite_len -eq 64 ]; then
					wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw psk ${key_overwrite}
				else
					wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw psk \"${key_overwrite}\"
				fi
				uci set wireless.${sect}.encryption='psk2'
				uci set wireless.${sect}.key=$key_overwrite
			;;
			WPA-PSK)
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw key_mgmt WPA-PSK
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw auth_alg OPEN
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw pairwise TKIP
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw proto WPA
				if [ $key_overwrite_len -eq 64 ]; then
					wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw psk ${key_overwrite}
				else
					wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw psk \"${key_overwrite}\"
				fi
				uci set wireless.${sect}.encryption='psk'
				uci set wireless.${sect}.key=$key_overwrite
			;;
			NONE)
				wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} set_network $nw key_mgmt NONE
				uci set wireless.${sect}.encryption='none'
				uci set wireless.${sect}.key=''
			;;
		esac
		wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} enable_network $nw
		wpa_cli -p /var/run/wpa_supplicant-${ifname_overwrite} save_config
	fi
}

psk=
ssid=
wpa_version=
IFNAME_OVERWRITE_AP=
IFNAME_OVERWRITE_STA=
wps_pbc_enhc_file=/var/run/wifi-wps-enhc-extn.conf

case "$CMD" in
	CONNECTED)
		wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME save_config
		ssid=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^ssid= | cut -f2- -d =)
		wpa_version=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^key_mgmt= | cut -f2- -d=)
		get_psk /var/run/wpa_supplicant-$IFNAME.conf
		wps_pbc_enhc_get_clone_config
		local sect=
		config_foreach is_section_ifname wifi-iface $IFNAME sect
		case $wpa_version in
			WPA2-PSK)
				uci set wireless.${sect}.encryption='psk2'
				uci set wireless.${sect}.key=$psk
				for intf in $IFNAME_OVERWRITE_AP; do
					wps_pbc_enhc_overwrite_ap_settings $intf $ssid WPA2PSK CCMP $psk
				done
				;;
			WPA-PSK)
				uci set wireless.${sect}.encryption='psk'
				uci set wireless.${sect}.key=$psk
				for intf in $IFNAME_OVERWRITE_AP; do
					wps_pbc_enhc_overwrite_ap_settings $intf $ssid WPAPSK TKIP $psk
				done
				;;
			NONE)
				uci set wireless.${sect}.encryption='none'
				uci set wireless.${sect}.key=''
				for intf in $IFNAME_OVERWRITE_AP; do
					wps_pbc_enhc_overwrite_ap_settings $intf $ssid OPEN NONE
				done
				;;
		esac
		uci set wireless.${sect}.ssid="$ssid"
		for intf in $IFNAME_OVERWRITE_STA; do
			[ "$IFNAME" != "$intf" ] && wps_pbc_enhc_overwrite_sta_settings $intf $ssid $wpa_version $psk
		done
		uci commit
		if [ -r /var/run/wifi-wps-enhc-extn.pid ]; then
			echo $IFNAME > /var/run/wifi-wps-enhc-extn.done
			kill -SIGUSR1 "$(cat "/var/run/wifi-wps-enhc-extn.pid")"
		fi
		kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
		#post hotplug event to whom take care of
		env -i ACTION="wps-connected" INTERFACE=$IFNAME /sbin/hotplug-call iface
		;;
	WPS-TIMEOUT)
		kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
		env -i ACTION="wps-timeout" INTERFACE=$IFNAME /sbin/hotplug-call iface
		;;
	DISCONNECTED)
		;;
esac

