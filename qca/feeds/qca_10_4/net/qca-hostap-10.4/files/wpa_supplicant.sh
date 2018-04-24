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

wpa_supplicant_setup_vif() {
	local vif="$1"
	local driver="$2"
	local key="$key"
	local options="$3"
	local freq="" crypto=""
	[ -n "$4" ] && freq="frequency=$4"

	# make sure we have the encryption type and the psk
	[ -n "$enc" ] || {
		config_get enc "$vif" encryption
	}

	enc_list=`echo "$enc" | sed "s/+/ /g"`

	for enc_var in $enc_list; do
		case "$enc_var" in
			*tkip)
				crypto="TKIP $crypto"
				;;
			*aes)
				crypto="CCMP $crypto"
				;;
			*ccmp)
				crypto="CCMP $crypto"
				;;
			*ccmp-256)
				crypto="CCMP-256 $crypto"
				;;
			*gcmp)
				crypto="GCMP $crypto"
				;;
			*gcmp-256)
				crypto="GCMP-256 $crypto"
		esac
	done

	[ -n "$key" ] || {
		config_get key "$vif" key
	}

	local net_cfg bridge
	config_get bridge "$vif" bridge
	[ -z "$bridge" ] && {
		net_cfg="$(find_net_config "$vif")"
		[ -z "$net_cfg" ] || bridge="$(bridge_interface "$net_cfg")"
		config_set "$vif" bridge "$bridge"
	}

	local mode ifname wds modestr=""
	config_get mode "$vif" mode
	config_get ifname "$vif" ifname
	config_get_bool wds "$vif" wds 0
	config_get_bool extap "$vif" extap 0

	config_get device "$vif" device
	config_get_bool qwrap_enable "$device" qwrap_enable 0

	[ -z "$bridge" ] || [ "$mode" = ap ] || [ "$mode" = sta -a $wds -eq 1 ] || \
	[ "$mode" = sta -a $extap -eq 1 ] || [ $qwrap_enable -ne 0 ] || {
		echo "wpa_supplicant_setup_vif($ifname): Refusing to bridge $mode mode interface"
		return 1
	}
	[ "$mode" = "adhoc" ] && modestr="mode=1"

	key_mgmt='NONE'
	case "$enc" in
		*none*) ;;
		*wep*)
			config_get key "$vif" key
			key="${key:-1}"
			case "$key" in
				[1234])
					for idx in 1 2 3 4; do
						local zidx
						zidx=$(($idx - 1))
						config_get ckey "$vif" "key${idx}"
						[ -n "$ckey" ] && \
							append "wep_key${zidx}" "wep_key${zidx}=$(prepare_key_wep "$ckey")"
					done
					wep_tx_keyidx="wep_tx_keyidx=$((key - 1))"
				;;
				*)
					wep_key0="wep_key0=$(prepare_key_wep "$key")"
					wep_tx_keyidx="wep_tx_keyidx=0"
				;;
			esac
			case "$enc" in
				*mixed*)
					wep_auth_alg='auth_alg=OPEN SHARED'
				;;
				*shared*)
					wep_auth_alg='auth_alg=SHARED'
				;;
				*open*)
					wep_auth_alg='auth_alg=OPEN'
				;;
			esac
		;;
		*psk*)
			key_mgmt='WPA-PSK'
			# if you want to use PSK with a non-nl80211 driver you
			# have to use WPA-NONE and wext driver for wpa_s
			[ "$mode" = "adhoc" -a "$driver" != "nl80211" ] && {
				key_mgmt='WPA-NONE'
				driver='wext'
			}
			if [ ${#key} -eq 64 ]; then
				passphrase="psk=${key}"
			else
				passphrase="psk=\"${key}\""
			fi

			[ -n "$crypto" ] || crypto="CCMP"
			pairwise="pairwise=$crypto"

			case "$enc" in
				*mixed*)
					proto='proto=RSN WPA'
				;;
				*psk2*)
					proto='proto=RSN'
					config_get ieee80211w "$vif" ieee80211w
				;;
				*psk*)
					proto='proto=WPA'
				;;
			esac
		;;
		*wpa*|*8021x*)
			proto='proto=WPA2'
			key_mgmt='WPA-EAP'
			config_get ieee80211w "$vif" ieee80211w
			config_get ca_cert "$vif" ca_cert
			config_get eap_type "$vif" eap_type
			ca_cert=${ca_cert:+"ca_cert=\"$ca_cert\""}

			[ -n "$crypto" ] || crypto="CCMP"
			pairwise="pairwise=$crypto"

			case "$eap_type" in
				tls)
					config_get identity "$vif" identity
					config_get client_cert "$vif" client_cert
					config_get priv_key "$vif" priv_key
					config_get priv_key_pwd "$vif" priv_key_pwd
					identity="identity=\"$identity\""
					client_cert="client_cert=\"$client_cert\""
					priv_key="private_key=\"$priv_key\""
					priv_key_pwd="private_key_passwd=\"$priv_key_pwd\""
				;;
				peap|ttls)
					config_get auth "$vif" auth
					config_get identity "$vif" identity
					config_get password "$vif" password
					phase2="phase2=\"auth=${auth:-MSCHAPV2}\""
					identity="identity=\"$identity\""
					password="password=\"$password\""
				;;
			esac
			eap_type="eap=$(echo $eap_type | tr 'a-z' 'A-Z')"
		;;
	esac

	keymgmt='NONE'

	# Allow SHA256
	case "$enc" in
		*wpa*|*8021x*) keymgmt=EAP;;
		*psk*) keymgmt=PSK;;
	esac

	case "$ieee80211w" in
		0)
			key_mgmt="WPA-${keymgmt}"
		;;
		1)
			key_mgmt="WPA-${keymgmt} WPA-${keymgmt}-SHA256"
		;;
		2)
			key_mgmt="WPA-${keymgmt}-SHA256"
		;;
	esac

	[ -n "$ieee80211w" ] && ieee80211w="ieee80211w=$ieee80211w"
	case "$pairwise" in
		*CCMP-256*) group="group=CCMP-256 GCMP-256 GCMP CCMP TKIP";;
		*GCMP-256*) group="group=GCMP-256 GCMP CCMP TKIP";;
		*GCMP*) group="group=GCMP CCMP TKIP";;
		*CCMP*) group="group=CCMP TKIP";;
		*TKIP*) group="group=TKIP";;
	esac

	config_get ifname "$vif" ifname
	config_get bridge "$vif" bridge
	config_get ssid "$vif" ssid
	config_get bssid "$vif" bssid
	bssid=${bssid:+"bssid=$bssid"}

	config_get_bool wps_pbc "$vif" wps_pbc 0

	config_get config_methods "$vif" wps_config
	[ "$wps_pbc" -gt 0 ] && append config_methods push_button

	[ -n "$config_methods" ] && {
		wps_cred="wps_cred_processing=2"
		wps_config_methods="config_methods=$config_methods"
		update_config="update_config=1"
		# fix the overlap session of WPS PBC for two STA vifs
		macaddr=$(cat /sys/class/net/${bridge}/address)
		uuid=$(echo "$macaddr" | sed 's/://g')
		[ -n "$uuid" ] && {
			uuid_config="uuid=87654321-9abc-def0-1234-$uuid"
		}
	}

	local ctrl_interface wait_for_wrap=""

	if [ $qwrap_enable -ne 0 ]; then
		ctrl_interface="/var/run/wpa_supplicant"
		if [ -f "/tmp/qwrap_conf_filename-$ifname.conf" ]; then
			rm -rf /tmp/qwrap_conf_filename-$ifname.conf
		fi
		echo -e "/var/run/wpa_supplicant-$ifname.conf \c\h" > /tmp/qwrap_conf_filename-$ifname.conf
		wait_for_wrap="-W"
	fi

	ctrl_interface="/var/run/wpa_supplicant-$ifname"

	rm -rf $ctrl_interface
	rm -f /var/run/wpa_supplicant-$ifname.conf
	cat > /var/run/wpa_supplicant-$ifname.conf <<EOF
ctrl_interface=$ctrl_interface
$wps_config_methods
$wps_cred
$update_config
$uuid_config
network={
	$modestr
	scan_ssid=1
	ssid="$ssid"
	$bssid
	key_mgmt=$key_mgmt
	$proto
	$freq
	$ieee80211w
	$passphrase
	$pairwise
	$group
	$eap_type
	$ca_cert
	$client_cert
	$priv_key
	$priv_key_pwd
	$phase2
	$identity
	$password
	$wep_key0
	$wep_key1
	$wep_key2
	$wep_key3
	$wep_tx_keyidx
	$wep_auth_alg
}
EOF
	[ -z "$proto" -a "$key_mgmt" != "NONE" ] || {\
                # If there is a change in path of wpa_supplicant-$ifname.lock file, please make the path
                # change also in wrapd_api.c file.
		[ -f "/var/run/wpa_supplicant-$ifname.lock" ] &&
			rm /var/run/wpa_supplicant-$ifname.lock
		wpa_cli -g /var/run/wpa_supplicantglobal interface_add  $ifname /var/run/wpa_supplicant-$ifname.conf athr /var/run/wpa_supplicant-$ifname "" $bridge
		touch /var/run/wpa_supplicant-$ifname.lock
    }
}

_wpa_supplicant_common() {
	local ifname="$1"

	_rpath="/var/run/wpa_supplicant"
	_config="${_rpath}-$ifname.conf"
}

wpa_supplicant_prepare_interface() {
	local ifname="$1"
	_w_driver="$2"

	_wpa_supplicant_common "$1"

	json_get_vars mode wds

	[ -n "$network_bridge" ] && {
		fail=
		case "$mode" in
			adhoc)
				fail=1
			;;
			sta)
				[ "$wds" = 1 ] || fail=1
			;;
		esac

		[ -n "$fail" ] && {
			wireless_setup_vif_failed BRIDGE_NOT_ALLOWED
			return 1
		}
	}

	local ap_scan=

	_w_mode="$mode"
	_w_modestr=

	[[ "$mode" = adhoc ]] && {
		ap_scan="ap_scan=2"

		_w_modestr="mode=1"
	}

	[[ "$mode" = mesh ]] && {
		user_mpm="user_mpm=1"
		mesh_ctrl_interface="ctrl_interface=$_rpath"
	}

	wpa_supplicant_teardown_interface "$ifname"
	cat > "$_config" <<EOF
$ap_scan
EOF
	return 0
}

wpa_supplicant_add_network() {
	local ifname="$1"

	_wpa_supplicant_common "$1"
	wireless_vif_parse_encryption

	json_get_vars \
		ssid bssid key basic_rate mcast_rate ieee80211w \
		wps_device_type wps_device_name wps_manufacturer \
		wps_config wps_model_name wps_model_number \
		wps_serial_number

	local key_mgmt='NONE'
	local enc_str=
	local network_data=
	local T="	"

	local wpa_key_mgmt="WPA-PSK"
	local scan_ssid="scan_ssid=1"
	local freq

	[[ "$_w_mode" = "adhoc" ]] && {
		append network_data "mode=1" "$N$T"
		[ -n "$channel" ] && {
			freq="$(get_freq "$phy" "$channel")"
			append network_data "fixed_freq=1" "$N$T"
			append network_data "frequency=$freq" "$N$T"
		}

		scan_ssid="scan_ssid=0"

		[ "$_w_driver" = "nl80211" ] ||	wpa_key_mgmt="WPA-NONE"
	}

	[[ "$_w_mode" = "mesh" ]] && {
		append network_data "mode=5" "$N$T"
		[ -n "$channel" ] && {
			freq="$(get_freq "$phy" "$channel")"
			append network_data "frequency=$freq" "$N$T"
		}
		wpa_key_mgmt="SAE"
		scan_ssid=""
	}

	[[ "$_w_mode" = "adhoc" -o "$_w_mode" = "mesh" ]] && append network_data "$_w_modestr" "$N$T"

	case "$auth_type" in
		none) ;;
		wep)
			local wep_keyidx=0
			hostapd_append_wep_key network_data
			append network_data "wep_tx_keyidx=$wep_keyidx" "$N$T"
		;;
		psk)
			local passphrase

			key_mgmt="$wpa_key_mgmt"
			if [ ${#key} -eq 64 ]; then
				passphrase="psk=${key}"
			else
				passphrase="psk=\"${key}\""
			fi
			append network_data "$passphrase" "$N$T"
		;;
		eap)
			key_mgmt='WPA-EAP'

			json_get_vars eap_type identity ca_cert
			[ -n "$ca_cert" ] && append network_data "ca_cert=\"$ca_cert\"" "$N$T"
			[ -n "$identity" ] && append network_data "identity=\"$identity\"" "$N$T"
			case "$eap_type" in
				tls)
					json_get_vars client_cert priv_key priv_key_pwd
					append network_data "client_cert=\"$client_cert\"" "$N$T"
					append network_data "private_key=\"$priv_key\"" "$N$T"
					append network_data "private_key_passwd=\"$priv_key_pwd\"" "$N$T"
				;;
				peap|ttls)
					json_get_vars auth password
					set_default auth MSCHAPV2
					append network_data "phase2=\"$auth\"" "$N$T"
					append network_data "password=\"$password\"" "$N$T"
				;;
			esac
			append network_data "eap=$(echo $eap_type | tr 'a-z' 'A-Z')" "$N$T"
		;;
		sae)
			local passphrase

			key_mgmt="$wpa_key_mgmt"
			if [ ${#key} -eq 64 ]; then
				passphrase="psk=${key}"
			else
				passphrase="psk=\"${key}\""
			fi
			append network_data "$passphrase" "$N$T"
		;;
	esac

	[ "$mode" = mesh ] || {
		case "$wpa" in
			1)
				append network_data "proto=WPA" "$N$T"
			;;
			2)
				append network_data "proto=RSN" "$N$T"
			;;
		esac

		case "$ieee80211w" in
			[012])
				[ "$wpa" -ge 2 ] && append network_data "ieee80211w=$ieee80211w" "$N$T"
			;;
		esac
	}
	local beacon_int brates mrate
	[ -n "$bssid" ] && append network_data "bssid=$bssid" "$N$T"
	[ -n "$beacon_int" ] && append network_data "beacon_int=$beacon_int" "$N$T"

	local bssid_blacklist bssid_whitelist
	json_get_values bssid_blacklist bssid_blacklist
	json_get_values bssid_whitelist bssid_whitelist

	[ -n "$bssid_blacklist" ] && append network_data "bssid_blacklist=$bssid_blacklist" "$N$T"
	[ -n "$bssid_whitelist" ] && append network_data "bssid_whitelist=$bssid_whitelist" "$N$T"

	[ -n "$basic_rate" ] && {
		local br rate_list=
		for br in $basic_rate; do
			wpa_supplicant_add_rate rate_list "$br"
		done
		[ -n "$rate_list" ] && append network_data "rates=$rate_list" "$N$T"
	}

	[ -n "$mcast_rate" ] && {
		local mc_rate=
		wpa_supplicant_add_rate mc_rate "$mcast_rate"
		append network_data "mcast_rate=$mc_rate" "$N$T"
	}

	local ht_str
	[[ "$_w_mode" = adhoc ]] || ibss_htmode=
	[ -n "$ibss_htmode" ] && append network_data "htmode=$ibss_htmode" "$N$T"

	config_methods=$wps_config
	[ -n "$config_methods" ] && {
		set_default wps_device_type "6-0050F204-1"
		set_default wps_device_name "Wireless Client"
		set_default wps_manufacturer "openwrt.org"
		set_default wps_model_name "cmodel"
		set_default wps_model_number "123"
		set_default wps_serial_number "12345"

		device_type="device_type=$wps_device_type"
		device_name="device_name=$wps_device_name"
		manufacturer="manufacturer=$wps_manufacturer"
		model_name="model_name=$wps_model_name"
		model_number="model_number=$wps_model_number"
		serial_number="serial_number=$wps_serial_number"
		config_methods="config_methods=$config_methods"
	}

	cat >> "$_config" <<EOF
$mesh_ctrl_interface
$user_mpm
$device_type
$device_name
$manufacturer
$model_name
$model_number
$serial_number
$config_methods

network={
	$scan_ssid
	ssid="$ssid"
	key_mgmt=$key_mgmt
	$network_data
}
EOF
	return 0
}

wpa_supplicant_run() {
	local ifname="$1"; shift

	_wpa_supplicant_common "$ifname"

	[ -f "${_rpath}-$ifname.lock" ] &&
		rm ${_rpath}-$ifname.lock
	wpa_cli -g ${_rpath}global interface_add  $ifname ${_config} nl80211 ${_rpath}-$ifname ""
	touch ${_rpath}-$ifname.lock
}
