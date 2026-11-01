/*
 *  llb_kern_quic_cid.h: LoxiLB eBPF NAT_LB_SEL_QUIC_CID endpoint selection
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 *
 * A QUIC short-header packet whose Destination Connection ID carries a server ID goes to
 * the active endpoint with that server ID, so that a client changing address stays on its
 * endpoint. Anything else takes the same path as NAT_LB_SEL_HASH; this selector never
 * drops a packet. It runs only on a conntrack miss.
 */
#ifndef __LLB_KERN_QUIC_CID_H__
#define __LLB_KERN_QUIC_CID_H__

#include "../common/llb_quic_cid.h"

#ifdef HAVE_LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") quic_cid_stats = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_quic_cid_stats),
  .max_entries = LLB_NATV4_MAP_ENTRIES
};
#else
struct quic_cid_stats_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_quic_cid_stats);
        __uint(max_entries, LLB_NATV4_MAP_ENTRIES);
} quic_cid_stats SEC(".maps");
#endif

static int __always_inline
dp_sel_quic_cid(void *ctx, struct xfi *xf, struct dp_proxy_tacts *act)
{
  struct dp_quic_cid_stats *st;
  struct mf_xfrm_inf *nxfrm_act;
  const __u8 *p;
  void *dend;
  __u32 key = act->ca.cidx;
  __u32 sid;
  uint16_t sel = -1;
  uint16_t i = 0;
  int parsed = 0;

  if (xf->l34m.nw_proto == IPPROTO_UDP && act->quic_sid_len == QUIC_SID_LEN) {
    p = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off + sizeof(struct udphdr));
    dend = DP_TC_PTR(DP_PDATA_END(ctx));

    if (quic_has_sid(p, dend) &&
        !quic_is_long(p[0]) && quic_fixed_bit_ok(p[0]) &&
        quic_cr(p[QUIC_DCID_OFF]) == act->quic_cr) {
      /* The packet is read here only: the loop compares this scalar, which keeps
       * the verifier's cost of the loop independent of the packet parsing. */
      sid = quic_sid_v4(p);
      parsed = 1;
      for (i = 0; i < LLB_MAX_NXFRMS && i < act->nxfrm; i++) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act->inactive == 0 && nxfrm_act->nat_xip4 == sid) {
          sel = i;
          break;
        }
      }
    }
  }

  st = bpf_map_lookup_elem(&quic_cid_stats, &key);
  if (st != NULL) {
    if (sel != (uint16_t)(-1)) {
      lock_xadd(&st->routed, 1);
    } else if (parsed) {
      lock_xadd(&st->miss, 1);
    } else {
      lock_xadd(&st->unroutable, 1);
    }
  }

  if (sel != (uint16_t)(-1)) {
    return sel;
  }

  /* A private copy of the NAT_LB_SEL_HASH branch, which stays untouched */
  sel = dp_get_pkt_hash(ctx) % act->nxfrm;
  if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
    /* Fall back if hash selection gives us a deadend */
    if (act->nxfrms[sel].inactive) {
      for (i = 0; i < LLB_MAX_NXFRMS; i++) {
        if (act->nxfrms[i].inactive == 0) {
          sel = i;
          break;
        }
      }
    }
  }
  return sel;
}

#endif /* __LLB_KERN_QUIC_CID_H__ */
