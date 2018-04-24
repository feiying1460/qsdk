#ifndef	__OL_IF_DFS_H__
#define	__OL_IF_DFS_H__

#if ATH_SUPPORT_DFS
extern	void ol_if_dfs_setup(struct ieee80211com *ic);
extern	void ol_if_dfs_teardown(struct ieee80211com *ic);
extern	void ol_if_dfs_configure(struct ieee80211com *ic);
#endif

#endif	/* __OL_IF_DFS_H__ */
