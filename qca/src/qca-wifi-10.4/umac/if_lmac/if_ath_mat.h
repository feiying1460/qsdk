#ifndef _IF_ATH_MAT_H_
#define _IF_ATH_MAT_H_

#include "wbuf.h"
#include "if_athvar.h"

int ath_wrap_mat_rx(struct ieee80211vap *in, wbuf_t m);
int ath_wrap_mat_tx(struct ieee80211vap * out, wbuf_t m);
#endif
