/*
 *  llb_quic_cid.h: QUIC-LB plaintext connection ID parsing
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 *
 * Pure inline helpers shared by the eBPF datapath and the userspace unit test.
 * They work on the UDP payload of a QUIC packet with a short header:
 *
 *   byte 0     flags (bit 7 = long header, bit 6 = fixed bit)
 *   byte 1     first octet of the Destination Connection ID: CR (3 bits) | len (5 bits)
 *   byte 2..5  server ID (draft-ietf-quic-load-balancers, plaintext layout)
 *
 * The server ID is the endpoint's IPv4 address in network order.
 */
#ifndef __LLB_QUIC_CID_H__
#define __LLB_QUIC_CID_H__

#include <linux/types.h>

#define QUIC_HDR_FORM_LONG  0x80
#define QUIC_HDR_FIXED_BIT  0x40
#define QUIC_DCID_OFF       1
#define QUIC_SID_OFF        2
#define QUIC_SID_LEN        4
#define QUIC_CR_SHIFT       5

#define QUIC_CID_INLINE static inline __attribute__((always_inline))

QUIC_CID_INLINE int
quic_is_long(__u8 b0)
{
  return (b0 & QUIC_HDR_FORM_LONG) != 0;
}

QUIC_CID_INLINE int
quic_fixed_bit_ok(__u8 b0)
{
  return (b0 & QUIC_HDR_FIXED_BIT) != 0;
}

QUIC_CID_INLINE __u8
quic_cr(__u8 dcid0)
{
  return dcid0 >> QUIC_CR_SHIFT;
}

/* Non-zero if the payload [p, end) is long enough to hold the flags, the first DCID
 * octet and the server ID, the bounds check quic_sid_v4() relies on.
 */
QUIC_CID_INLINE int
quic_has_sid(const __u8 *p, const void *end)
{
  return (const void *)(p + QUIC_SID_OFF + QUIC_SID_LEN) <= end;
}

/* The server ID of a payload that passed quic_has_sid(), in network order, comparable
 * with an IPv4 address as stored. The BPF target splits a memcpy with no alignment into
 * byte loads, so it gets a single 4-byte load, which the verifier allows at this offset.
 */
QUIC_CID_INLINE __u32
quic_sid_v4(const __u8 *p)
{
#ifdef __bpf__
  return *(const __u32 *)(p + QUIC_SID_OFF);
#else
  __u32 sid;

  __builtin_memcpy(&sid, p + QUIC_SID_OFF, sizeof(sid));
  return sid;
#endif
}

#endif /* __LLB_QUIC_CID_H__ */
