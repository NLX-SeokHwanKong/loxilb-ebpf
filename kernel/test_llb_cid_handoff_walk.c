// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Unit test for the userspace handoff walk using linker-wrapped map operations.
#include "loxilb_libdp.c"
#include <assert.h>

enum operation { NONE, LOOKUP, DELETE, NEXT };

static llb_dp_struct_t test_dp;
static enum operation faulty_op;
static int operation_errno;
static unsigned int successful_deletes;

static const struct dp_nat_key service = {
  .daddr = {10}, .dport = 100, .zone = 1, .l4proto = IPPROTO_UDP
};
static const struct dp_cid_reply_key arm = {
  .vip = 11, .backend = 21, .sport = 200, .zone = 1
};
static const struct llb_cid_detach scope = {
  .service = &service, .arms = &arm, .count = 1, .rid = 7
};
static const struct dp_fcv4_key keys[] = {
  {.saddr = 31, .daddr = 10, .dport = 100, .l4proto = IPPROTO_UDP},
  {.saddr = 32, .daddr = 10, .dport = 100, .l4proto = IPPROTO_UDP}
};

static int
missing(int error)
{
  errno = error;
  return -1;
}

int
__wrap_bpf_map_get_next_key(int fd, const void *opaque_key, void *next)
{
  (void)fd;
  const struct dp_fcv4_key *key = opaque_key;
  if (!key) {
    memcpy(next, &keys[0], sizeof(keys[0]));
    return 0;
  }
  if (key->saddr == keys[0].saddr) {
    if (faulty_op == NEXT)
      return missing(operation_errno);
    memcpy(next, &keys[1], sizeof(keys[1]));
    return 0;
  }
  assert(key->saddr == keys[1].saddr);
  return missing(ENOENT);
}

int
__wrap_bpf_map_lookup_elem(int fd, const void *opaque_key, void *value)
{
  (void)fd;
  const struct dp_fcv4_key *key = opaque_key;
  if (faulty_op == LOOKUP && key->saddr == keys[0].saddr)
    return missing(operation_errno);
  struct dp_fc_tacts *fc = value;
  memset(fc, 0, sizeof(*fc));
  fc->zone = service.zone;
  struct dp_fc_tact *dnat = &fc->fcta[DP_SET_DNAT];
  dnat->ca.act_type = DP_SET_DNAT;
  dnat->nat_act.rid = scope.rid;
  dnat->nat_act.rip[0] = arm.vip;
  dnat->nat_act.xip[0] = arm.backend;
  dnat->nat_act.xport = arm.sport;
  return 0;
}

int
__wrap_bpf_map_delete_elem(int fd, const void *opaque_key)
{
  (void)fd;
  const struct dp_fcv4_key *key = opaque_key;
  if (faulty_op == DELETE && key->saddr == keys[0].saddr)
    return missing(operation_errno);
  successful_deletes++;
  return 0;
}

int
main(void)
{
  static const struct {
    const char *name;
    enum operation op;
    int error, expected;
    uint32_t limit;
    bool verify;
    unsigned int deletes;
  } cases[] = {
    {"first lookup vanished", LOOKUP, ENOENT, 0, 2, false, 1},
    {"first deletion vanished", DELETE, ENOENT, 0, 2, false, 1},
    {"lookup error", LOOKUP, EIO, -EIO, 2, false, 0},
    {"deletion error", DELETE, EIO, -EIO, 2, false, 0},
    {"iterator error", NEXT, EIO, -EIO, 2, false, 0},
    {"walk bound after lookup miss", LOOKUP, ENOENT, -EAGAIN, 1, false, 0},
    {"verify remaining key after lookup miss", LOOKUP, ENOENT, -EBUSY, 2, true, 0},
    {"ordinary walk", NONE, 0, 0, 2, false, 2},
  };

  xh = &test_dp;
  for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    faulty_op = cases[i].op;
    operation_errno = cases[i].error;
    successful_deletes = 0;
    xh->maps[LL_DP_FCV4_MAP].map_fd = 42;
    xh->maps[LL_DP_FCV4_MAP].max_entries = cases[i].limit;
    unsigned int removed = 0;
    int rc = llb_cid_handoff_walk(&scope, LL_DP_FCV4_MAP, cases[i].verify, &removed);
    printf("%s: rc=%d removed=%u\n", cases[i].name, rc, removed);
    assert(rc == cases[i].expected);
    assert(removed == cases[i].deletes);
    assert(removed == successful_deletes);
  }
  return 0;
}

