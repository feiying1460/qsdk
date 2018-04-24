#include <ieee80211_var.h>
#include <ieee80211_regdmn.h>

/*
 * Start the process of sending a CSA and doing a channel switch.
 *
 * By setting IEEE80211_F_CHANSWITCH, the beacon update code
 * will add a CSA IE.  Once the count reaches 0, the channel
 * switch will occur.
 */
void
ieee80211_start_csa(struct ieee80211com *ic, u_int8_t ieeeChan)
{
#ifdef MAGPIE_HIF_GMAC
	struct ieee80211vap *tmp_vap = NULL;
#endif
#if ATH_SUPPORT_IBSS_DFS
        struct ieee80211vap *vap = NULL;
#endif
	IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
	    "Beginning CSA to channel %d\n", ieeeChan);

	ic->ic_chanchange_chan = ieeeChan;
	ic->ic_chanchange_tbtt = ic->ic_chan_switch_cnt;
#ifdef MAGPIE_HIF_GMAC
	TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
		ic->ic_chanchange_cnt += ic->ic_chanchange_tbtt;
	}
#endif
	ic->ic_flags |= IEEE80211_F_CHANSWITCH;
#if ATH_SUPPORT_IBSS_DFS
        vap = TAILQ_FIRST(&ic->ic_vaps);
        while ((vap != NULL) && (vap->iv_ic != ic))
        {
            vap = TAILQ_NEXT(vap, iv_next);
        }
        if ((vap != NULL) && (vap->iv_opmode == IEEE80211_M_IBSS) && 
            IEEE80211_ADDR_EQ(vap->iv_ibssdfs_ie_data.owner, vap->iv_myaddr))
        {
            ieee80211_dfs_action(vap, NULL);
            //vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_CHANNEL_SWITCH;
            //ieee80211_ibss_beacon_update_start(ic);
        }
#endif
}
