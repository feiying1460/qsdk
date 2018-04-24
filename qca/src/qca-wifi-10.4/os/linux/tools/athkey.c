/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * athkey [-i interface] keyix cipher keyval
 * (default interface is wifi0).
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>

#include <stdio.h>
#include <ctype.h>
#include <getopt.h>

/*
 * Linux uses __BIG_ENDIAN and __LITTLE_ENDIAN while BSD uses _foo
 * and an explicit _BYTE_ORDER.  Sorry, BSD got there first--define
 * things in the BSD way...
 */
#define	_LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#define	_BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */
#ifndef ATH_SUPPORT_LINUX_STA
#include <asm/byteorder.h>
#endif
#if defined(__LITTLE_ENDIAN)
#define	_BYTE_ORDER	_LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define	_BYTE_ORDER	_BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#include "net80211/ieee80211.h"
#include "net80211/ieee80211_crypto.h"
#include "net80211/ieee80211_ioctl.h"

static	int s = -1;
const char *progname;

static void
checksocket()
{
	if (s < 0 ? (s = socket(AF_INET, SOCK_DGRAM, 0)) == -1 : 0)
		perror("socket(SOCK_DRAGM)");
}

static int
set80211priv(const char *dev, int op, void *data, int len, int show_err)
{
	struct iwreq iwr;

	checksocket();

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(s, op, &iwr) < 0) {
		if (show_err) {
			static const char *opnames[] = {
				"ioctl[IEEE80211_IOCTL_SETPARAM]",
				"ioctl[IEEE80211_IOCTL_GETPARAM]",
				"ioctl[IEEE80211_IOCTL_SETKEY]",
				"ioctl[IEEE80211_IOCTL_GETKEY]",
				"ioctl[IEEE80211_IOCTL_DELKEY]",
				NULL,
				"ioctl[IEEE80211_IOCTL_SETMLME]",
				NULL,
				"ioctl[IEEE80211_IOCTL_SETOPTIE]",
				"ioctl[IEEE80211_IOCTL_GETOPTIE]",
				"ioctl[IEEE80211_IOCTL_ADDMAC]",
				NULL,
				"ioctl[IEEE80211_IOCTL_DELMAC]",
				"ioctl[IEEE80211_IOCTL_GETCHANLIST]",
				"ioctl[IEEE80211_IOCTL_SETCHANLIST]",
			};
			if (IEEE80211_IOCTL_SETPARAM <= op &&
			    op <= IEEE80211_IOCTL_SETCHANLIST)
				perror(opnames[op - SIOCIWFIRSTPRIV]);
			else
				perror("ioctl[unknown???]");
		}
		return -1;
	}
	return 0;
}

static int
digittoint(int c)
{
	return isdigit(c) ? c - '0' : isupper(c) ? c - 'A' + 10 : c - 'a' + 10;
}

static int
getdata(const char *arg, u_int8_t *data, size_t maxlen)
{
	const char *cp = arg;
	int len;

	if (cp[0] == '0' && (cp[1] == 'x' || cp[1] == 'X'))
		cp += 2;
	len = 0;
	while (*cp) {
		int b0, b1;
		if (cp[0] == ':' || cp[0] == '-' || cp[0] == '.') {
			cp++;
			continue;
		}
		if (!isxdigit(cp[0])) {
			fprintf(stderr, "%s: invalid data value %c (not hex)\n",
				progname, cp[0]);
			exit(-1);
		}
		b0 = digittoint(cp[0]);
		if (cp[1] != '\0') {
			if (!isxdigit(cp[1])) {
				fprintf(stderr, "%s: invalid data value %c "
					"(not hex)\n", progname, cp[1]);
				exit(-1);
			}
			b1 = digittoint(cp[1]);
			cp += 2;
		} else {			/* fake up 0<n> */
			b1 = b0, b0 = 0;
			cp += 1;
		}
		if (len > maxlen) {
			fprintf(stderr,
				"%s: too much data in %s, max %u bytes\n",
				progname, arg, maxlen);
		}
		data[len++] = (b0<<4) | b1;
	}
	return len;
}

static int
getcipher(const char *name)
{
#define	streq(a,b)	(strcasecmp(a,b) == 0)

	if (streq(name, "wep"))
		return IEEE80211_CIPHER_WEP;
	if (streq(name, "tkip"))
		return IEEE80211_CIPHER_TKIP;
	if (streq(name, "aes-ocb") || streq(name, "ocb"))
		return IEEE80211_CIPHER_AES_OCB;
	if (streq(name, "aes-ccm") || streq(name, "ccm") ||
	    streq(name, "aes"))
		return IEEE80211_CIPHER_AES_CCM;
	if (streq(name, "ckip"))
		return IEEE80211_CIPHER_CKIP;
	if (streq(name, "none") || streq(name, "clr"))
		return IEEE80211_CIPHER_NONE;

	fprintf(stderr, "%s: unknown cipher %s\n", progname, name);
	exit(-1);
#undef streq
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-i device] keyix cipher keyval [mac]\n",
		progname);
	exit(-1);
}

int
main(int argc, char *argv[])
{
	const char *ifname = "wifi0";
	struct ieee80211req_key setkey;
	struct ieee80211req_del_key delkey;
	const char *cp;
	int c, keyix;
	int op = IEEE80211_IOCTL_SETKEY;

	progname = argv[0];
	while ((c = getopt(argc, argv, "di:")) != -1)
		switch (c) {
		case 'd':
			op = IEEE80211_IOCTL_DELKEY;
			break;
		case 'i':
			ifname = optarg;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	keyix = atoi(argv[0]);
	if (!(1 <= keyix && keyix <= 4))
		errx(-1, "%s: invalid key index %s, must be [1..4]",
			progname, argv[0]);
	switch (op) {
	case IEEE80211_IOCTL_DELKEY:
		memset(&delkey, 0, sizeof(delkey));
		delkey.idk_keyix = keyix-1;
		return set80211priv(ifname, op, &delkey, sizeof(delkey), 1);
	case IEEE80211_IOCTL_SETKEY:
		if (argc != 3 && argc != 4)
			usage();
		memset(&setkey, 0, sizeof(setkey));
		setkey.ik_flags = IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV;
		setkey.ik_keyix = keyix-1;
		setkey.ik_type = getcipher(argv[1]);
		setkey.ik_keylen = getdata(argv[2], setkey.ik_keydata,
			sizeof(setkey.ik_keydata));
		if (argc == 4)
			(void) getdata(argv[3], setkey.ik_macaddr,
				IEEE80211_ADDR_LEN);
		return set80211priv(ifname, op, &setkey, sizeof(setkey), 1);
	}
	return -1;
}
