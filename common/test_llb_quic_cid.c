/*
 *  test_llb_quic_cid.c: unit test for llb_quic_cid.h
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 *
 * Build and run with: make quic-cid-test
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include "llb_quic_cid.h"

static int failed;

#define CHECK(cond)                                           \
do {                                                          \
  if (!(cond)) {                                              \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
    failed++;                                                 \
  }                                                           \
} while (0)

/* A short-header packet as Envoy's QUIC-LB generator emits it: flags, then a 10-byte
 * DCID for server ID 192.0.2.22, nonce 2c5042b8, worker 00. */
static const __u8 pkt[] = { 0x40, 0x08, 0xc0, 0x00, 0x02, 0x16, 0x2c, 0x50, 0x42, 0xb8, 0x00 };

static void
test_header_bits(void)
{
  CHECK(quic_is_long(0xc0));
  CHECK(quic_is_long(0x80));
  CHECK(!quic_is_long(0x40));
  CHECK(!quic_is_long(0x00));
  CHECK(quic_fixed_bit_ok(0x40));
  CHECK(quic_fixed_bit_ok(0xc0));
  CHECK(!quic_fixed_bit_ok(0x80));
  CHECK(!quic_fixed_bit_ok(0x00));
}

static void
test_cr(void)
{
  int cr;

  for (cr = 0; cr < 8; cr++) {
    CHECK(quic_cr((__u8)((cr << 5) | 0x08)) == cr);
    CHECK(quic_cr((__u8)((cr << 5) | 0x1f)) == cr);
  }
  CHECK(quic_cr(pkt[QUIC_DCID_OFF]) == 0);
}

static void
test_sid(void)
{
  CHECK(quic_sid_v4(pkt) == inet_addr("192.0.2.22"));
  CHECK(quic_sid_v4(pkt) != inet_addr("192.0.2.21"));
  CHECK(quic_sid_v4(pkt) != inet_addr("193.0.2.22"));
  CHECK(quic_sid_v4(pkt) != inet_addr("192.1.2.22"));
  CHECK(quic_sid_v4(pkt) != inet_addr("192.0.3.22"));
}

static void
test_sid_unaligned(void)
{
  /* The server ID follows whatever headers precede the payload, so try every alignment. */
  __u8 buf[16] = { 0 };
  unsigned int off;

  for (off = 0; off < 8; off++) {
    __u8 *p = buf + off;

    p[QUIC_SID_OFF] = 0xc0;
    p[QUIC_SID_OFF + 1] = 0x00;
    p[QUIC_SID_OFF + 2] = 0x02;
    p[QUIC_SID_OFF + 3] = 0x16;
    CHECK(quic_sid_v4(p) == inet_addr("192.0.2.22"));
  }
}

static void
test_bounds(void)
{
  unsigned int avail;

  /* Flags, the first DCID octet and the server ID are 6 bytes; every shorter payload fails. */
  for (avail = 0; avail < 6; avail++) {
    CHECK(!quic_has_sid(pkt, pkt + avail));
  }
  CHECK(quic_has_sid(pkt, pkt + 6));
  CHECK(quic_has_sid(pkt, pkt + sizeof(pkt)));
}

int
main(void)
{
  test_header_bits();
  test_cr();
  test_sid();
  test_sid_unaligned();
  test_bounds();
  if (failed) {
    printf("quic-cid-test: %d check(s) failed\n", failed);
    return EXIT_FAILURE;
  }
  printf("quic-cid-test: all checks passed\n");
  return EXIT_SUCCESS;
}
