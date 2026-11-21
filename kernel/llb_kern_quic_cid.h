/*
 *  llb_kern_quic_cid.h: LoxiLB eBPF NAT_LB_SEL_QUIC_CID endpoint selection
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 *
 * A QUIC short-header packet whose Destination Connection ID carries a server ID goes to
 * the active endpoint with that server ID, so that a client changing address stays on its
 * endpoint. On an IPv4 FullNAT rule with the legacy profile, a decoded SID
 * with no active endpoint must not start a new hashed conntrack. Packets
 * without a decoded SID can still enter by the normal hash rule.
 * This selector runs on conntrack misses.
 */
#ifndef __LLB_KERN_QUIC_CID_H__
#define __LLB_KERN_QUIC_CID_H__

#include "../common/llb_quic_cid.h"

#define QUIC_CID_NO_ACTIVE_SID ((__u16)0xfffe)

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
  __u32 sid = 0;
  uint16_t sel = -1;
  uint16_t i = 0;
  int parsed = 0;

  if (xf->l34m.nw_proto == IPPROTO_UDP && act->quic_sid_len == QUIC_SID_LEN) {
    if (act->quic_profile == LLB_QUIC_PROFILE_LEGACY &&
        (act->opflags & NAT_LB_OP_CID_REPLY_GUARD)) {
#ifdef LL_TC_EBPF
      /* skb data_end can stop at the linear head even though the UDP
       * datagram contains a CID. Read the bounded prefix across skb frags.
       */
      struct {
        struct udphdr udp;
        __u8 payload[QUIC_SID_OFF + QUIC_SID_LEN];
      } prefix;
      const __u32 need = sizeof(prefix.udp) + sizeof(prefix.payload);

      if (dp_pktbuf_read(ctx, xf->pm.l4_off, &prefix, need) == 0 &&
          bpf_ntohs(prefix.udp.len) >= need &&
          !quic_is_long(prefix.payload[0]) &&
          quic_fixed_bit_ok(prefix.payload[0]) &&
          quic_cr(prefix.payload[QUIC_DCID_OFF]) == act->quic_cr) {
        __builtin_memcpy(&sid, prefix.payload + QUIC_SID_OFF, sizeof(sid));
        parsed = 1;
      }
#else
      p = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off + sizeof(struct udphdr));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (quic_has_sid(p, dend) && !quic_is_long(p[0]) &&
          quic_fixed_bit_ok(p[0]) && quic_cr(p[QUIC_DCID_OFF]) == act->quic_cr) {
        sid = quic_sid_v4(p);
        parsed = 1;
      }
#endif
    } else {
      p = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off + sizeof(struct udphdr));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));

#ifdef HAVE_DP_QUIC_CID_V3
      const struct udphdr *udp = (const struct udphdr *)(p - sizeof(*udp));
      int cid_ok = 0;

      if (quic_has_sid(p, dend)) {
        if (act->quic_profile == LLB_QUIC_PROFILE_LEGACY) {
          cid_ok = !quic_is_long(p[0]) && quic_fixed_bit_ok(p[0]) &&
                   quic_cr(p[QUIC_DCID_OFF]) == act->quic_cr;
        } else if (act->quic_profile == LLB_QUIC_PROFILE_MVFST_V3 &&
                   (const void *)(udp + 1) <= dend) {
          __u16 udp_len = bpf_ntohs(udp->len);

          if (udp_len >= sizeof(*udp)) {
            cid_ok = quic_is_mvfst_v3(p, dend, udp_len - sizeof(*udp));
          }
        }
      }
      if (cid_ok && quic_has_sid(p, dend)) {
#else
      if (quic_has_sid(p, dend) &&
          !quic_is_long(p[0]) && quic_fixed_bit_ok(p[0]) &&
          quic_cr(p[QUIC_DCID_OFF]) == act->quic_cr) {
#endif
        sid = quic_sid_v4(p);
        parsed = 1;
      }
    }

    if (parsed) {
      /* Compare the decoded scalar in the loop to bound verifier work. */
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

  if (parsed && act->quic_profile == LLB_QUIC_PROFILE_LEGACY &&
      (act->opflags & NAT_LB_OP_CID_REPLY_GUARD))
    return QUIC_CID_NO_ACTIVE_SID;

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
