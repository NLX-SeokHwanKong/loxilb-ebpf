// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#include "loxilb_libdp.c"
#include <assert.h>

enum { GUARD_FD = 41, RETIRED_FD, NAT_FD, CT_FD, FC_FD };

struct reservation {
  struct dp_cid_reply_key key;
  __u32 refs;
  bool used;
};

static llb_dp_struct_t test_dp;
static struct reservation guard[5];
static struct dp_proxy_tacts published;
static uint32_t capacity, inserts, walks, deleted, publishes;
static int insertion_error;
static unsigned int warnings;
static char warning[160];

static void
capture_warning(log_Event *event)
{
  if (event->level == LOG_WARN) {
    warnings++;
    vsnprintf(warning, sizeof(warning), event->fmt, event->ap);
  }
}

static int
fail(int error)
{
  errno = error;
  return -1;
}

static struct dp_cid_reply_key
reply_key(unsigned int id)
{
  return (struct dp_cid_reply_key){.vip = 11, .backend = id, .sport = 200, .zone = 1};
}

static int
find_key(const struct dp_cid_reply_key *key)
{
  for (uint32_t i = 0; i < capacity; i++)
    if (guard[i].used && memcmp(&guard[i].key, key, sizeof(*key)) == 0)
      return i;
  return -1;
}

static void
seed(unsigned int slot, unsigned int id, __u32 refs)
{
  guard[slot] = (struct reservation){.key = reply_key(id), .refs = refs, .used = true};
}

int
__wrap_bpf_map_get_next_key(int fd, const void *key, void *next)
{
  if (fd == CT_FD || fd == FC_FD)
    return fail(ENOENT);
  assert(fd == GUARD_FD);
  walks++;
  uint32_t start = key ? find_key(key) + 1 : 0;
  for (uint32_t i = start; i < capacity; i++) {
    if (!guard[i].used)
      continue;
    memcpy(next, &guard[i].key, sizeof(guard[i].key));
    return 0;
  }
  return fail(ENOENT);
}

int
__wrap_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
  const struct dp_cid_reply_key *reply = key;
  if (fd == RETIRED_FD) {
    if (reply->backend == 8)
      return fail(EIO);
    if (reply->backend == 2 || reply->backend == 3) {
      uint64_t deadline = reply->backend == 2 ? 0 : UINT64_MAX;
      memcpy(value, &deadline, sizeof(deadline));
      return 0;
    }
    return fail(ENOENT);
  }

  assert(fd == GUARD_FD);
  int slot = find_key(reply);
  if (slot < 0)
    return fail(ENOENT);
  memcpy(value, &guard[slot].refs, sizeof(guard[slot].refs));
  return 0;
}

int
__wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
  if (fd == NAT_FD) {
    assert(flags == BPF_ANY);
    memcpy(&published, value, sizeof(published));
    publishes++;
    return 0;
  }

  assert(fd == GUARD_FD);
  int slot = find_key(key);
  if (flags == BPF_EXIST) {
    assert(slot >= 0);
  } else {
    assert(flags == BPF_NOEXIST && slot < 0);
    inserts++;
    if (insertion_error)
      return fail(insertion_error);
    for (uint32_t i = 0; i < capacity; i++) {
      if (!guard[i].used) {
        slot = i;
        break;
      }
    }
    if (slot < 0)
      return fail(E2BIG);
  }
  guard[slot].key = *(const struct dp_cid_reply_key *)key;
  guard[slot].refs = *(const __u32 *)value;
  guard[slot].used = true;
  return 0;
}

int
__wrap_bpf_map_delete_elem(int fd, const void *key)
{
  assert(fd == GUARD_FD);
  int slot = find_key(key);
  assert(slot >= 0);
  memset(&guard[slot], 0, sizeof(guard[slot]));
  deleted++;
  return 0;
}

static void
reset(uint32_t limit)
{
  capacity = limit;
  inserts = walks = deleted = publishes = 0;
  insertion_error = 0;
  warnings = 0;
  warning[0] = 0;
  memset(guard, 0, sizeof(guard));
  xh = &test_dp;
  xh->maps[LL_DP_CID_REPLY_GUARD_MAP].map_fd = GUARD_FD;
  xh->maps[LL_DP_CID_REPLY_GUARD_MAP].max_entries = limit;
  xh->maps[LL_DP_CID_RETIRED_MAP].map_fd = RETIRED_FD;
  xh->maps[LL_DP_NAT_MAP].map_fd = NAT_FD;
  xh->maps[LL_DP_CT_MAP].map_fd = CT_FD;
  xh->maps[LL_DP_FCV4_MAP].map_fd = FC_FD;
}

static int
slot(unsigned int id)
{
  struct dp_cid_reply_key key = reply_key(id);
  return find_key(&key);
}

static void
full_then_retry(void)
{
  reset(5);
  seed(0, 1, 0);
  seed(1, 2, 0);
  seed(2, 3, 0);
  seed(3, 4, 1);
  seed(4, 5, CID_REPLY_WITHDRAWN | 2);
  struct dp_cid_reply_key fresh = reply_key(6);

  assert(llb_cid_reply_acquire(&fresh) == 1);
  assert(inserts == 2 && walks == 6 && deleted == 2);
  assert(slot(1) == -1 && slot(2) == -1 && slot(6) >= 0);
  puts("full map reclaims both eligible keys and retries exactly once: PASS");
  assert(slot(3) >= 0 && guard[slot(3)].refs == 0);
  puts("unexpired retired entry keeps its zero-valued reservation: PASS");
  assert(slot(4) >= 0 && guard[slot(4)].refs == 1);
  assert(slot(5) >= 0 && guard[slot(5)].refs == (CID_REPLY_WITHDRAWN | 2));
  puts("both positive reference forms are preserved: PASS");
}

static void
full_without_eligible_keys(void)
{
  reset(3);
  seed(0, 4, 1);
  seed(1, 3, 0);
  struct dp_nat_key rule = {.daddr = {11}, .dport = 100, .zone = 1, .l4proto = IPPROTO_UDP};
  struct dp_proxy_tacts old = {
    .ca = {.act_type = DP_SET_DNAT, .cidx = 7},
    .sel_type = NAT_LB_SEL_QUIC_CID, .opflags = NAT_LB_OP_CID_REPLY_GUARD, .nxfrm = 1
  };
  old.nxfrms[0] = (struct mf_xfrm_inf){.nat_rip = {11}, .nat_xip = {4}, .nat_xport = 200};
  struct dp_proxy_tacts next = old;
  next.nxfrm = 3;
  next.nxfrms[1] = (struct mf_xfrm_inf){.nat_rip = {11}, .nat_xip = {6}, .nat_xport = 200};
  next.nxfrms[2] = (struct mf_xfrm_inf){.nat_rip = {11}, .nat_xip = {7}, .nat_xport = 200};
  struct reservation before[5];
  memcpy(before, guard, sizeof(guard));
  published = old;

  assert(llb_cid_reply_update(&rule, &old, &next) == -1);
  assert(publishes == 0 && inserts == 3 && walks == 4 && deleted == 1);
  assert(memcmp(before, guard, sizeof(guard)) == 0);
  assert(memcmp(&published, &old, sizeof(old)) == 0 && cid_pending_count == 0);
  puts("no eligible entries: failed NAT update rolls back its partial reservation: PASS");
}

static void
noncapacity_error_and_fast_path(void)
{
  reset(3);
  seed(0, 1, 0);
  struct dp_cid_reply_key fresh = reply_key(6);

  insertion_error = ENOMEM;
  assert(llb_cid_reply_acquire(&fresh) == -1 && errno == ENOMEM);
  assert(inserts == 1 && walks == 0 && deleted == 0 && slot(1) >= 0);
  puts("non-capacity insertion error never starts reclaim: PASS");
  insertion_error = 0;
  assert(llb_cid_reply_acquire(&fresh) == 1);
  assert(inserts == 2 && walks == 0 && deleted == 0 && slot(1) >= 0);
  puts("below capacity uses the original fast path: PASS");
}

static void
warn_if_retry_still_fails(void)
{
  reset(1);
  seed(0, 3, 0);
  struct dp_cid_reply_key fresh = reply_key(6);
  char expected[160];

  assert(llb_cid_reply_acquire(&fresh) == -1 && errno == E2BIG);
  assert(inserts == 2 && walks == 2 && deleted == 0 && warnings == 1);
  snprintf(expected, sizeof(expected),
           "CID reply guard full after reclaim: rule update deferred (scanned=1, errno=%d)", E2BIG);
  assert(strcmp(warning, expected) == 0);
  puts("failed retry warns exactly once with scan count and preserves errno: PASS");
}

static void
keep_zero_on_retired_lookup_error(void)
{
  reset(2);
  seed(0, 8, 0);
  seed(1, 1, 0);
  struct dp_cid_reply_key fresh = reply_key(6);

  assert(llb_cid_reply_acquire(&fresh) == 1);
  assert(slot(8) >= 0 && guard[slot(8)].refs == 0);
  assert(slot(1) == -1 && slot(6) >= 0 && deleted == 1 && warnings == 0);
  puts("zero reservation survives a retired-map lookup error other than ENOENT: PASS");
}

int
main(void)
{
  assert(log_add_callback(capture_warning, NULL, LOG_WARN) == 0);
  full_then_retry();
  full_without_eligible_keys();
  noncapacity_error_and_fast_path();
  warn_if_retry_still_fails();
  keep_zero_on_retired_lookup_error();
  return 0;
}
