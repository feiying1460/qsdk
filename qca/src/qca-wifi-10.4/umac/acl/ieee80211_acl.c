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


#include <ieee80211_var.h>
#include "ieee80211_ioctl.h"

#include "ieee80211_band_steering.h"

#if UMAC_SUPPORT_ACL

/*! \file ieee80211_acl.c
**  \brief 
**
** Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
** Copyright (c) 2004-2007 Atheros Communications, Inc.
**
 */

/*
 * IEEE 802.11 MAC ACL support.
 *
 * When this module is loaded the sender address of each received
 * frame is passed to the iac_check method and the module indicates
 * if the frame should be accepted or rejected.  If the policy is
 * set to ACL_POLICY_OPEN then all frames are accepted w/o checking
 * the address.  Otherwise, the address is looked up in the database
 * and if found the frame is either accepted (ACL_POLICY_ALLOW)
 * or rejected (ACL_POLICY_DENT).
 */

enum
{
    ACL_POLICY_OPEN             = 0,/* open, don't check ACL's */
    ACL_POLICY_ALLOW	        = 1,/* allow traffic from MAC */
    ACL_POLICY_DENY             = 2,/* deny traffic from MAC */
};

#define	ACL_HASHSIZE	32

/* Macros to check if the flag passed belong to both ACL lists */
#define IS_PART_OF_BOTH_ACL_LIST (IEEE80211_ACL_FLAG_ACL_LIST_1 | IEEE80211_ACL_FLAG_ACL_LIST_2)

/* 
 * The ACL list is accessed from process context when ioctls are made to add,
 * delete mac entries or set/get policy (read/write operations). It is also 
 * accessed in tasklet context for read purposes only. Hence, we must use
 * spinlocks with DPCs disabled to protect this list. 
 * 
 * It may be noted that ioctls are serialized by the big kernel lock in Linux 
 * and so the process context code does not use mutual exclusion. It may not
 * be true for other OSes. In such cases, this code must be made safe for 
 * ioctl mutual exclusion. 
 */
struct ieee80211_acl_entry
{
    /* 
     * list element for linking on acl_list 
     */
    TAILQ_ENTRY(ieee80211_acl_entry)     ae_list; 

    /* 
     * list element for linking on acl_hash list 
     */
    LIST_ENTRY(ieee80211_acl_entry)      ae_hash; 

    u_int8_t                             ae_macaddr[IEEE80211_ADDR_LEN];

    /*
     * Flags that indicate how the ACL should behave under other conditions
     * as needed by band steering (or potentially other modules in the
     * future).
     */
    u_int8_t                             ae_flags;
};
struct ieee80211_acl
{
    osdev_t                              acl_osdev;
    spinlock_t                           acl_lock;
    int                                  acl_policy;              /* ACL policy for first ACL entry */
    int                                  acl_policy_sec;          /* ACL policy for secondary ACL entry */
    TAILQ_HEAD(, ieee80211_acl_entry)    acl_list;                /* List of all ACL entries */
    ATH_LIST_HEAD(, ieee80211_acl_entry) acl_hash[ACL_HASHSIZE];
};

/* 
 * simple hash is enough for variation of macaddr 
 */
#define	ACL_HASH(addr)	\
    (((const u_int8_t *)(addr))[IEEE80211_ADDR_LEN - 1] % ACL_HASHSIZE)

static void acl_free_all_locked(ieee80211_acl_t acl, u_int8_t acl_list_id);
static int ieee80211_acl_check_list(struct ieee80211_acl_entry *entry, u_int8_t policy,
                                                enum ieee80211_acl_flag acl_list_id);

int ieee80211_acl_attach(wlan_if_t vap)
{
    ieee80211_acl_t acl;

    if (vap->iv_acl)
        return EOK; /* already attached */

    acl = (ieee80211_acl_t) OS_MALLOC(vap->iv_ic->ic_osdev, 
                                sizeof(struct ieee80211_acl), 0);
    if (acl) {
        OS_MEMZERO(acl, sizeof(struct ieee80211_acl));
        acl->acl_osdev  = vap->iv_ic->ic_osdev;
        vap->iv_acl = acl;

        spin_lock_init(&acl->acl_lock);
        TAILQ_INIT(&acl->acl_list);
        acl->acl_policy = ACL_POLICY_OPEN;

        return EOK;
    }

    return ENOMEM;
}

int ieee80211_acl_detach(wlan_if_t vap)
{
    ieee80211_acl_t acl;

    if (vap->iv_acl == NULL)
        return EINPROGRESS; /* already detached or never attached */

    acl = vap->iv_acl;
    acl_free_all_locked(acl, IS_PART_OF_BOTH_ACL_LIST);

    spin_lock_destroy(&acl->acl_lock);

    OS_FREE(acl);

    vap->iv_acl = NULL;

    return EOK;
}

static __inline struct ieee80211_acl_entry * 
_find_acl(ieee80211_acl_t acl, const u_int8_t *macaddr)
{
    struct ieee80211_acl_entry *entry;
    int hash;

    hash = ACL_HASH(macaddr);
    LIST_FOREACH(entry, &acl->acl_hash[hash], ae_hash) {
        if (IEEE80211_ADDR_EQ(entry->ae_macaddr, macaddr))
            return entry;
    }
    return NULL;
}

/* 
 * This function is always called from tasklet context and it may be noted
 * that the same tasklet is not scheduled on more than one CPU at the same 
 * time. The user context functions that modify the ACL use spin_lock_dpc 
 * which disable softIrq on the current CPU. However, a softIrq scheduled 
 * on another CPU could execute the rx tasklet. Hence, protection is needed 
 * here. spinlock is sufficient as it disables kernel preemption and if the 
 * user task is accessing this list, the rx tasklet will wait until the user 
 * task releases the spinlock. The original code didn't use any protection.
 */
int 
ieee80211_acl_check(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN])
{
    struct ieee80211_acl_entry *entry;
    ieee80211_acl_t acl = vap->iv_acl;
    int allow_acl = 0, allow_acl_sec = 0;

    if (acl == NULL) return 1;

    /* EV : 89216
     * WPS2.0 : Ignore MAC Address Filtering if WPS Enabled
     * Display the message.
     * return 1 to report success
     */
    if(vap->iv_wps_mode) {
        /* Only disallow ACL while not using band steering
           and if its not a public vap when ssid steering is enabled */
        if ((!ieee80211_bsteering_is_vap_enabled(vap)) && (vap->iv_vap_ssid_config)) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n WPS Enabled : Ignoring MAC Filtering\n");
            return 1;
        }
    }

    /* If both ACL policies are open mode, then return 1 */
    if (!acl->acl_policy && !acl->acl_policy_sec)
        return 1;

    spin_lock(&acl->acl_lock);
    entry = _find_acl(acl, mac);
    spin_unlock(&acl->acl_lock);

    /* If the entry is permitted by both ACL lists, then return 1 */
    allow_acl = ieee80211_acl_check_list(entry,
                        acl->acl_policy, IEEE80211_ACL_FLAG_ACL_LIST_1);
    if(allow_acl == 1)
        allow_acl_sec = ieee80211_acl_check_list(entry,
                        acl->acl_policy_sec, IEEE80211_ACL_FLAG_ACL_LIST_2);
    return allow_acl_sec;

}

int ieee80211_acl_check_list(struct ieee80211_acl_entry *entry, u_int8_t policy,
                                                enum ieee80211_acl_flag acl_list_id) {

    int allow_entry = 0;

   /* -> If the ACL policy is OPEN, then return 1.
    * -> If the ACL policy is ALLOW, then return 1 if the entry is part
    *    of the given ACL list.
    * -> If the ACL policy is DENY, then return 1 if the entry is not part
    *    of the given ACL list.
    */
    switch (policy) {
        case ACL_POLICY_OPEN:
            allow_entry = 1;
            break;
        case ACL_POLICY_ALLOW:
            if(entry != NULL)
                allow_entry = !!(entry->ae_flags & acl_list_id);
            break;
        case ACL_POLICY_DENY:
            if(entry != NULL)
                allow_entry = !(entry->ae_flags & acl_list_id);
            else
                allow_entry = 1;
            break;
    }
    return allow_entry;
}

#if ATH_BAND_STEERING
/**
 * @brief Determine if the flag is set on the ACL entry or not.
 *
 * @param [in] vap  the interface on which to check
 * @param [in] mac  the MAC address of the entry to check
 * @param [in] flag  the flag that is being checked; multiple flags can
 *                   be checked (with all having to be set)
 *
 * @return 1 if the flag is set; otherwise 0
 */
int
ieee80211_acl_flag_check(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                         enum ieee80211_acl_flag flag)
{
    ieee80211_acl_t acl = vap->iv_acl;
    struct ieee80211_acl_entry *entry;
    int retval = 0;

    if (acl == NULL) return 0;

    spin_lock(&acl->acl_lock);
    entry = _find_acl(acl, mac);
    if (entry &&
        (entry->ae_flags & flag) == flag) {
        retval = 1;
    }
    spin_unlock(&acl->acl_lock);

    return retval;
}

/**
 * @brief Enable the flag on the ACL entry.
 *
 * @param [in] vap  the interface on which to manipulate an ACL entry
 * @param [in] mac  the MAC address of the entry to change
 * @param [in] flag  the flag (or flags) to set
 *
 * @return EOK on success; ENOENT if the entry cannot be found
 */
int
ieee80211_acl_set_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_acl_flag flag)
{
    ieee80211_acl_t acl = vap->iv_acl;
    struct ieee80211_acl_entry *entry;
    int retval = -ENOENT;

    if (acl) {
        spin_lock(&acl->acl_lock);
        entry = _find_acl(acl, mac);
        if (entry) {
            entry->ae_flags |= flag;
            retval = EOK;
        }
        spin_unlock(&acl->acl_lock);
    }

    return retval;
}

/**
 * @brief Disable the flag on the ACL entry.
 *
 * @param [in] vap  the interface on which to manipulate an ACL entry
 * @param [in] mac  the MAC address of the entry to change
 * @param [in] flag  the flag (or flags) to clear
 *
 * @return EOK on success; ENOENT if the entry cannot be found
 */
int
ieee80211_acl_clr_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_acl_flag flag)
{
    ieee80211_acl_t acl = vap->iv_acl;
    struct ieee80211_acl_entry *entry;
    int retval = -ENOENT;

    if (acl) {
        spin_lock(&acl->acl_lock);
        entry = _find_acl(acl, mac);
        if (entry) {
            entry->ae_flags &= ~flag;
            retval = EOK;
        }
        spin_unlock(&acl->acl_lock);
    }

    return retval;
}
#endif /* ATH_BAND_STEERING */

/* 
 * The ACL list is modified when in user context and the list needs to be 
 * protected from rx tasklet. Using spin_lock alone won't be sufficient as
 * that only disables task pre-emption and not irq or softIrq preemption.
 * Hence, effective protection is possible only by disabling softIrq on
 * local CPU and spin_lock_bh needs to be used.
 */
int 
ieee80211_acl_add(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id)
{
    ieee80211_acl_t acl = vap->iv_acl;
    struct ieee80211_acl_entry *entry, *new;
    int hash, rc;

    if (acl == NULL) {
        rc = ieee80211_acl_attach(vap);
        if (rc != EOK) return rc;
        acl = vap->iv_acl;
    }

    hash = ACL_HASH(mac);
    spin_lock_bh(&acl->acl_lock);
    LIST_FOREACH(entry, &acl->acl_hash[hash], ae_hash) {
        if (IEEE80211_ADDR_EQ(entry->ae_macaddr, mac)) {
           /* return EEXIST only if mac is part of the same logical ACL list,
            * that is primary or secondary ACL. Otherwise we want to
            * update the flags field and return OK.
            */
            if (!(entry->ae_flags & acl_list_id)) {
                entry->ae_flags |= acl_list_id;
                spin_unlock_bh(&acl->acl_lock);
                return 0;
            }
            spin_unlock_bh(&acl->acl_lock);
            return EEXIST;
        }
    }
    new = (struct ieee80211_acl_entry *) OS_MALLOC(acl->acl_osdev,
                                              sizeof(struct ieee80211_acl_entry), 0);
    if (new == NULL)
        return ENOMEM;

    IEEE80211_ADDR_COPY(new->ae_macaddr, mac);
    new->ae_flags = acl_list_id;
    TAILQ_INSERT_TAIL(&acl->acl_list, new, ae_list);
    LIST_INSERT_HEAD(&acl->acl_hash[hash], new, ae_hash);
    spin_unlock_bh(&acl->acl_lock);

    return 0;
}

static void
_acl_free(ieee80211_acl_t acl, struct ieee80211_acl_entry *entry)
{
    TAILQ_REMOVE(&acl->acl_list, entry, ae_list);
    LIST_REMOVE(entry, ae_hash);
    OS_FREE(entry);
}

int 
ieee80211_acl_remove(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id)
{
    ieee80211_acl_t acl = vap->iv_acl;
    struct ieee80211_acl_entry *entry;

    if (acl == NULL) return EINVAL;

    spin_lock_dpc(&acl->acl_lock);
    entry = _find_acl(acl, mac);
    if (entry != NULL) {
        /* Clear the flag corresponding to that ACL list */
        entry->ae_flags &= ~acl_list_id;

        /* If both the lists don't contain the macaddress, then remove it */
        if (!(entry->ae_flags & IS_PART_OF_BOTH_ACL_LIST))
            _acl_free(acl, entry);
    }
    spin_unlock_dpc(&acl->acl_lock);

    return (entry == NULL ? ENOENT : 0);
}

int 
ieee80211_acl_get(wlan_if_t vap, u_int8_t *mac_list, int len, int *num_mac, u_int8_t acl_list_id)
{
    ieee80211_acl_t acl = vap->iv_acl;
    struct ieee80211_acl_entry *entry;
	int rc;

    if (acl == NULL) {
        rc = ieee80211_acl_attach(vap);
        if (rc != EOK) return rc;
        acl = vap->iv_acl;
    }

    if ((mac_list == NULL) || (!len)) {
        return ENOMEM;
	}

    *num_mac = 0;

    spin_lock_dpc(&acl->acl_lock);
    TAILQ_FOREACH(entry, &acl->acl_list, ae_list) {
        len -= IEEE80211_ADDR_LEN;
        if (len < 0) {
            spin_unlock_dpc(&acl->acl_lock);
            return E2BIG;
        }
        if (entry->ae_flags & acl_list_id) {
            IEEE80211_ADDR_COPY(&(mac_list[*num_mac*IEEE80211_ADDR_LEN]), entry->ae_macaddr);
            (*num_mac)++;
        }
    }
    spin_unlock_dpc(&acl->acl_lock);

    return 0;
}

static void
acl_free_all_locked(ieee80211_acl_t acl, u_int8_t acl_list_id)
{
    struct ieee80211_acl_entry *entry, *next_entry;

    spin_lock_dpc(&acl->acl_lock); 
    entry = TAILQ_FIRST(&acl->acl_list);
    do {
            if (!entry)
                break;
            /*
             * If mac entry is present in the list, then clear that coresponding ACL
             * list flag. If that mac entry is not used by any ACL lists, free it
             * or iterate to the next mac entry in the list.
             */
            entry->ae_flags &= ~acl_list_id;
            next_entry = TAILQ_NEXT(entry, ae_list);
            if (!(entry->ae_flags & IS_PART_OF_BOTH_ACL_LIST))
               _acl_free(acl, entry);
            entry = next_entry;
    } while (next_entry != NULL);
    spin_unlock_dpc(&acl->acl_lock);
}

int ieee80211_acl_flush(wlan_if_t vap, u_int8_t acl_list_id)
{
    ieee80211_acl_t acl = vap->iv_acl;
    if (acl == NULL) return EINVAL;
    acl_free_all_locked(acl, acl_list_id);
    return 0;
}

int ieee80211_acl_setpolicy(wlan_if_t vap, int policy, u_int8_t acl_list_id)
{
    ieee80211_acl_t acl = vap->iv_acl;
    int rc;

    if (acl == NULL) {
        rc = ieee80211_acl_attach(vap);
        if (rc != EOK) return rc;
        acl = vap->iv_acl;
    }
    switch (policy)
    {
        case IEEE80211_MACCMD_POLICY_OPEN:
            if (acl_list_id == IEEE80211_ACL_FLAG_ACL_LIST_1)
                acl->acl_policy = ACL_POLICY_OPEN;
            else
                acl->acl_policy_sec = ACL_POLICY_OPEN;
            break;
        case IEEE80211_MACCMD_POLICY_ALLOW:
            if (acl_list_id == IEEE80211_ACL_FLAG_ACL_LIST_1)
                acl->acl_policy = ACL_POLICY_ALLOW;
            else
                acl->acl_policy_sec = ACL_POLICY_ALLOW;
            break;
        case IEEE80211_MACCMD_POLICY_DENY:
            if (acl_list_id == IEEE80211_ACL_FLAG_ACL_LIST_1)
                acl->acl_policy = ACL_POLICY_DENY;
            else
                acl->acl_policy_sec = ACL_POLICY_DENY;
            break;
        default:
            return EINVAL;
    }
    return 0;
}

int ieee80211_acl_getpolicy(wlan_if_t vap, u_int8_t acl_list_id)
{
    ieee80211_acl_t acl = vap->iv_acl;
    int rc;
    
    if (acl == NULL) {
        rc = ieee80211_acl_attach(vap);
        if (rc != EOK) return rc;
        acl = vap->iv_acl;
    }

    if (acl == NULL) return EINVAL;
    if (acl_list_id == IEEE80211_ACL_FLAG_ACL_LIST_1)
        return acl->acl_policy;
    else
        return acl->acl_policy_sec;
}

int wlan_set_acl_policy(wlan_if_t vap, int policy, u_int8_t acl_list_id)
{
    switch (policy) {
    case IEEE80211_MACCMD_POLICY_OPEN:
    case IEEE80211_MACCMD_POLICY_ALLOW:
    case IEEE80211_MACCMD_POLICY_DENY:
        ieee80211_acl_setpolicy(vap, policy, acl_list_id);
        break;
    case IEEE80211_MACCMD_FLUSH:
        ieee80211_acl_flush(vap, acl_list_id);
        break;
    case IEEE80211_MACCMD_DETACH:
        ieee80211_acl_detach(vap);
        break;
    }    

    return 0;
}

int wlan_get_acl_policy(wlan_if_t vap, u_int8_t acl_list_id)
{
    return ieee80211_acl_getpolicy(vap, acl_list_id);
}

int wlan_set_acl_add(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id)
{
    return ieee80211_acl_add(vap, mac, acl_list_id);
}

int wlan_set_acl_remove(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id)
{
    return ieee80211_acl_remove(vap, mac, acl_list_id);
}

int wlan_get_acl_list(wlan_if_t vap, u_int8_t *mac_list, int len, int *num_mac, u_int8_t acl_list_id)
{
    return ieee80211_acl_get(vap, mac_list, len, num_mac, acl_list_id);
}
#endif /* UMAC_SUPPORT_ACL */

