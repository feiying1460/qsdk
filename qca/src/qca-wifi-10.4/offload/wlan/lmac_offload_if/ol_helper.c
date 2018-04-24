#include "ol_if_athvar.h"
#include "htc_packet.h"
#include "ol_helper.h"
void
ol_cookie_init(void *ar)
{
    A_UINT32 i;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ar;
    struct ol_ath_cookie *scn_cookie = &scn->scn_cookie;
    scn_cookie->cookie_list = NULL;
    scn_cookie->cookie_count = 0;
    OS_MEMZERO(scn_cookie->s_cookie_mem, sizeof(scn_cookie->s_cookie_mem));
    qdf_spinlock_create(&(scn_cookie->cookie_lock));
    for (i = 0; i < MAX_COOKIE_NUM; i++) {
	ol_free_cookie(ar, &(scn_cookie->s_cookie_mem[i]));
    }
}

/* cleanup cookie queue */
void
ol_cookie_cleanup(void *ar)
{
    /* It is gone .... */
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ar;
    struct ol_ath_cookie *scn_cookie = &scn->scn_cookie;
    qdf_spin_lock_bh(&(scn_cookie->cookie_lock));
    scn_cookie->cookie_list = NULL;
    scn_cookie->cookie_count = 0;
    qdf_spin_unlock_bh(&(scn_cookie->cookie_lock));
}

void
ol_free_cookie(void *ar, struct cookie *cookie)
{	
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ar;
    struct ol_ath_cookie *scn_cookie = &scn->scn_cookie;
    qdf_spin_lock_bh(&(scn_cookie->cookie_lock));
    cookie->arc_list_next = scn_cookie->cookie_list;
    scn_cookie->cookie_list = cookie;
    scn_cookie->cookie_count++;
    qdf_spin_unlock_bh(&(scn_cookie->cookie_lock));
}

/* cleanup cookie queue */
struct cookie *
ol_alloc_cookie(void  *ar)

{
    struct cookie   *cookie;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ar;
    struct ol_ath_cookie *scn_cookie = &scn->scn_cookie;
    qdf_spin_lock_bh(&(scn_cookie->cookie_lock));
    cookie = scn_cookie->cookie_list;
    if(cookie != NULL)
    {
        scn_cookie->cookie_list = cookie->arc_list_next;
        scn_cookie->cookie_count--;
    }
    qdf_spin_unlock_bh(&(scn_cookie->cookie_lock));
    return cookie;
}

