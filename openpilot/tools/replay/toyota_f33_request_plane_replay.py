from __future__ import annotations

import argparse
import heapq
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path

from openpilot.tools.lib.logreader import LogReader
from opendbc.car import structs
from opendbc.car.toyota.interface import CarInterface
from opendbc.car.toyota.values import CAR, EPS_SCALE, ToyotaSafetyFlags
from opendbc.safety.tests.libsafety import libsafety_py
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  decode_sync,
  NATIVE_08A_ADDR,
  ORACLE_BUS,
  ORACLE_RESPONSE_ADDR,
  ToyotaTss3RequestProxy,
  build_oracle_transport,
  resolve_epoch,
)

parser = argparse.ArgumentParser(description="Replay F33 native inputs through current controller, signer adapter, and Panda safety")
parser.add_argument("route", type=Path)
parser.add_argument("--oracle-response-delay-ms", type=float, default=8.0)
parser.add_argument("--drop-sign-response", type=int, metavar="N", help="drop the Nth sign response to exercise fail-open/re-arm")
args = parser.parse_args()
files = sorted(args.route.glob('*/rlog.zst'), key=lambda p: int(p.parent.name.rsplit('--', 1)[1]))
if not files:
  raise RuntimeError(f"no rlogs under {args.route}")

# Extract only native CAN + recorded CarControl. Old host traffic is evidence for
# truth anchors only; it is never fed back into the current implementation.
events = []
cp_bytes = None
sync_seq = []
native_seq = []
recorded_oracle_tx = []
recorded_oracle_rx = []
HISTORICAL_ORACLE_REQUEST_ADDR = 0x7A1
HISTORICAL_ORACLE_RESPONSE_ADDR = 0x7A9
order = 0
for f in files:
  for m in LogReader(str(f), sort_by_time=False):
    t = int(m.logMonoTime)
    if m.which() == 'carParams' and cp_bytes is None:
      cp_bytes = m.carParams.as_builder().to_bytes()
    elif m.which() == 'can':
      for x in m.can:
        d, a, s = bytes(x.dat), int(x.address), int(x.src)
        if a == HISTORICAL_ORACLE_RESPONSE_ADDR and s == ORACLE_BUS and len(d) == 8 and d[:2] == b'\x07\xc9':
          recorded_oracle_rx.append((t, d))
      frames = [(int(x.address), bytes(x.dat), int(x.src)) for x in m.can
                if int(x.src) < 128 and int(x.address) not in (HISTORICAL_ORACLE_RESPONSE_ADDR, ORACLE_RESPONSE_ADDR)]
      if frames:
        events.append((t, 0, order, 'can', frames))
        order += 1
        for a, d, s in frames:
          if a == 0x00F and s == 0 and len(d) == 8:
            sync_seq.append((t, order, d))
          elif a == NATIVE_08A_ADDR and s == 2 and len(d) == 32:
            native_seq.append((t, order, d))
    elif m.which() == 'sendcan':
      for x in m.sendcan:
        if int(x.address) == HISTORICAL_ORACLE_REQUEST_ADDR and int(x.src) == ORACLE_BUS and len(x.dat) == 8:
          recorded_oracle_tx.append((t, bytes(x.dat)))
    elif m.which() == 'carControl':
      events.append((t, 1, order, 'cc', m.carControl.as_builder().to_bytes()))
      order += 1
if cp_bytes is None:
  raise RuntimeError('missing CarParams')
events.sort()
sync_seq.sort()
native_seq.sort()

# Independent full-message truth. Within each resolved reset epoch, native F33
# begins at message counter 1 and advances with B26. Hardware-recorded oracle
# responses below independently anchor this reconstruction.
sts = [x[0] for x in sync_seq]
epoch_by_frame = {}
epoch_groups = {}
epoch_order = []
for t, ord_, d in native_seq:
  j = bisect_right(sts, t) - 1
  if j < 0:
    continue
  trip, reset = decode_sync(sync_seq[j][2])
  ep = resolve_epoch(trip, reset, (d[28] >> 4) & 3)
  if ep is None:
    continue
  epoch_by_frame[d] = ep
  if ep not in epoch_groups:
    epoch_groups[ep] = []
    epoch_order.append(ep)
  epoch_groups[ep].append((t, ord_, d))

truth_by_frame = {}
truth_ambiguous = []
for ep in epoch_order:
  rows = epoch_groups[ep]
  candidates = []
  for _, _, start in rows:
    if ((start[28] >> 6) & 3) != 1:
      continue
    sb = start[26] & 0x3F
    seen, distances, ok = set(), [], True
    for _, _, d in rows:
      dist = ((d[26] & 0x3F) - sb) & 0x3F
      if dist in seen or dist > 31 or ((dist + 1) & 3) != ((d[28] >> 6) & 3):
        ok = False
        break
      seen.add(dist)
      distances.append(dist)
    if ok:
      candidates.append((max(distances), sb))
  if not candidates:
    truth_ambiguous.append((ep, 'none'))
    continue
  candidates.sort()
  if len(candidates) > 1 and candidates[1][0] == candidates[0][0]:
    truth_ambiguous.append((ep, 'tie'))
    continue
  sb = candidates[0][1]
  for _, _, d in rows:
    truth_by_frame[d] = (((d[26] & 0x3F) - sb) & 0x3F) + 1

# Validate independent truth against retained real EPS oracle responses.
def mac28(frame: bytes) -> str:
  return frame[28:32].hex()[1:]

recorded_requests = []
i = 0
recorded_oracle_tx.sort()
while i < len(recorded_oracle_tx):
  t, frame = recorded_oracle_tx[i]
  if frame[:2] != b'\x10\x28':
    i += 1
    continue
  nsdu = bytearray(frame[2:])
  j = i + 1
  sn = 1
  while j < len(recorded_oracle_tx) and len(nsdu) < 40 and recorded_oracle_tx[j][1][0] == (0x20 | sn):
    nsdu.extend(recorded_oracle_tx[j][1][1:])
    sn += 1
    j += 1
  if len(nsdu) >= 40:
    nsdu = bytes(nsdu[:40])
    if nsdu[:2] == b'\xc9\xc9' and nsdu[39] == (nsdu[2] ^ 0xFF):
      recorded_requests.append((t, nsdu[2], nsdu[3:39]))
  i = max(i + 1, j)
responses_by_seq = defaultdict(list)
for t, frame in recorded_oracle_rx:
  responses_by_seq[frame[2]].append((t, frame))
native_by_application = defaultdict(list)
for _, _, d in native_seq:
  if d in epoch_by_frame:
    native_by_application[d[:28]].append(d)
anchor_count = 0
for t, seq, domain in recorded_requests:
  response = next((frame for rt, frame in responses_by_seq[seq] if rt >= t and rt - t < 500_000_000), None)
  if response is None:
    continue
  packed = int.from_bytes(domain[32:36], 'big')
  ep = (int.from_bytes(domain[30:32], 'big'), (packed >> 12) & 0xFFFFF)
  candidate = (packed >> 4) & 0xFF
  cmac28 = response[4:8].hex()[:7]
  for d in native_by_application.get(domain[2:30], []):
    if epoch_by_frame.get(d) == ep and mac28(d) == cmac28 and d in truth_by_frame:
      anchor_count += 1
      assert truth_by_frame[d] == candidate, (truth_by_frame[d], candidate)
      break
if anchor_count == 0:
  raise RuntimeError('no retained hardware oracle anchors')

# Start before the second complete epoch so the new runtime must passively seed
# itself from a real epoch boundary; no synthetic recovery is provided.
if len(epoch_order) < 2:
  raise RuntimeError('route has fewer than two resolved epochs')
truth_boundary = min(t for t, _, _ in epoch_groups[epoch_order[1]])
pre_sync = [t for t, _, _ in sync_seq if t <= truth_boundary]
replay_floor = max(pre_sync) if pre_sync else truth_boundary
events = [e for e in events if e[0] >= replay_floor]
start_ns, end_ns = events[0][0], events[-1][0]
replay_native = [d for t, _, d in native_seq if t >= replay_floor]
truth_by_proxy_index = {}

print('events', len(events), 'native', len(replay_native), 'epochs', len(epoch_order),
      'anchors', anchor_count, 'ambiguous', len(truth_ambiguous), 'duration_s', (end_ns-start_ns)/1e9)

# Current production safety parameter, not the historical route's rollout bits.
param = (EPS_SCALE[CAR.TOYOTA_CAMRY_TSS3] | ToyotaSafetyFlags.F33 |
         ToyotaSafetyFlags.STOCK_LONGITUDINAL | ToyotaSafetyFlags.TSS3_08A_HOST)
safety = libsafety_py.libsafety
assert safety.set_safety_hooks(structs.CarParams.SafetyModel.toyota, int(param)) == 0
safety.init_tests()

sim = [0.0]
now_ns = [start_ns]
current_cs = [None]
echo_queue = []
scheduled = []
schedule_serial = 0
stats = Counter()
failures = []
strict_active_native = strict_host_id11 = 0
native_blocked = native_leaked = 0
safety_invalid = False
sign_generation_count = 0
drop_exercised = False


def packet(addr, bus, data):
  p = libsafety_py.make_CANPacket(addr, bus, data)
  if len(data) > 8:
    p[0].fd = 1
  return p


def set_clock(ns):
  now_ns[0] = ns
  sim[0] = (ns - start_ns) / 1e9
  safety.set_timer((ns // 1000) % 0xFFFFFFFF)


def host_tx(msgs):
  global strict_host_id11
  for m in msgs:
    if hasattr(m, 'address'):
      address, data, bus = int(m.address), bytes(m.dat), int(m.src)
    else:
      address, data, bus = int(m[0]), bytes(m[1]), int(m[2])
    ok = bool(safety.safety_tx_hook(packet(address, bus, data)))
    stats[('host_tx', hex(address), 'A' if ok else 'R')] += 1
    if ok and address == 0x777 and data[:3] == bytes((7, 0xC9, 0xA8)):
      stats['arm' if data[3] else 'release'] += 1
    if ok and address == NATIVE_08A_ADDR:
      stats['host_08a_accepted'] += 1
    if not ok:
      if address == NATIVE_08A_ADDR and not safety.get_controls_allowed():
        stats['expected_controls_disallowed_08a_reject'] += 1
      else:
        failures.append(('safety_tx_reject', sim[0], hex(address), safety.get_desired_angle_last(),
                         safety.get_angle_meas_min(), safety.get_angle_meas_max(), data.hex()))
    if address == NATIVE_08A_ADDR and proxy.active and proxy.control_lat_active:
      d = data
      if (d[21] & 0x3F) != 11:
        failures.append(('owned_non_id11_tx', sim[0], d[21] & 0x3F, d.hex()))
      else:
        strict_host_id11 += 1
    echo_queue.append((address, data, bus + (0x80 if ok else 0xC0)))


def drain_echo():
  while echo_queue and current_cs[0] is not None:
    a, d, s = echo_queue.pop(0)
    proxy.update([(now_ns[0], [(a, d, s)])], current_cs[0])


def oracle_cmac(job):
  truth = truth_by_proxy_index.get(job.native_index)
  if truth is None:
    failures.append(('oracle_truth_unknown', sim[0], job.native_index))
  elif job.message_counter != truth:
    failures.append(('wrong_sign_message_counter', sim[0], job.native_index, job.message_counter, truth))
  return bytes.fromhex('12345678')


with structs.CarParams.from_bytes(cp_bytes) as cp:
  ci = CarInterface(cp)
  proxy = ToyotaTss3RequestProxy(host_tx, start_thread=False, monotonic=lambda: sim[0])

  def schedule(when, kind, seq, job):
    global schedule_serial
    schedule_serial += 1
    heapq.heappush(scheduled, (when, schedule_serial, kind, seq, job))

  def deliver_due():
    while scheduled and scheduled[0][0] <= sim[0] + 1e-12:
      _, _, kind, seq, job = heapq.heappop(scheduled)
      if current_cs[0] is None or kind != 'response':
        continue
      data = bytes((0xC9, seq, 0, seq ^ 0xFF)) + oracle_cmac(job)
      proxy.update([(now_ns[0], [(ORACLE_RESPONSE_ADDR, data, ORACLE_BUS)])], current_cs[0])
      drain_echo()

  def run_oracle_step():
    global sign_generation_count, drop_exercised
    with proxy._cv:
      item = proxy._next_job_locked(sim[0])
    if item is None:
      return
    seq, job = item
    frames = build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter)
    host_tx(frames)
    drain_echo()
    stats['oracle_request_batches'] += 1
    sign_generation_count += 1
    if args.drop_sign_response is not None and sign_generation_count == args.drop_sign_response:
      drop_exercised = True
      stats['injected_sign_drop'] += 1
    else:
      schedule(sim[0] + args.oracle_response_delay_ms / 1000.0, 'response', seq, job)

  def advance_to(target_ns):
    while now_ns[0] + 1_000_000 < target_ns:
      set_clock(now_ns[0] + 1_000_000)
      deliver_due()
      run_oracle_step()
      deliver_due()
      drain_echo()
    set_clock(target_ns)
    deliver_due()
    run_oracle_step()
    deliver_due()
    drain_echo()

  was_lat_active = False
  was_enabled = False
  active_windows = 0
  enabled_windows = 0
  for _idx, (t, _prio, _ord, kind, payload) in enumerate(events):
    advance_to(t)
    if kind == 'can':
      for a, d, s in payload:
        fwd = safety.safety_fwd_hook(s, a)
        if a == NATIVE_08A_ADDR and s == 2 and proxy.active:
          strict_active_native += 1
          if fwd == -1:
            native_blocked += 1
          else:
            native_leaked += 1
            failures.append(('native_leak', sim[0], fwd, d[26] & 0x3F))
        if not safety.safety_rx_hook(packet(a, s, d)):
          stats[('rx_invalid', hex(a), s)] += 1
      current_cs[0] = ci.update([(t, payload)])
      for a, d, s in payload:
        before_index = proxy.native_index
        proxy.update([(t, [(a, d, s)])], current_cs[0])
        if a == NATIVE_08A_ADDR and s == 2 and proxy.native_index == before_index + 1:
          truth_by_proxy_index[proxy.native_index] = truth_by_frame.get(d)
          if proxy.freshness_ready:
            expected_counter = truth_by_proxy_index[proxy.native_index]
            if expected_counter is not None and proxy.tracker.message_counter != expected_counter:
              failures.append(('tracker_truth_mismatch', sim[0], proxy.native_index,
                               proxy.tracker.message_counter, expected_counter))
            stats['freshness_ready_native_updates'] += 1
      drain_echo()
      if sim[0] > 2.0:
        safety.safety_tick_current_safety_config()
        safety_invalid |= not safety.safety_config_valid()
    else:
      with structs.CarControl.from_bytes(payload) as CC:
        if proxy.consume_handoff_completed() and current_cs[0] is not None:
          ci.CC.reset_tss3_lateral_target(current_cs[0].steeringAngleDeg + current_cs[0].steeringAngleOffsetDeg)
        out, can_sends = ci.apply(CC, t)
        if can_sends:
          host_tx(can_sends)
          drain_echo()
        proxy.set_control(CC.enabled, CC.latActive, out.steeringAngleDeg)
        drain_echo()
        if bool(CC.latActive) and not was_lat_active:
          active_windows += 1
        if bool(CC.enabled) and not was_enabled:
          enabled_windows += 1
        was_lat_active = bool(CC.latActive)
        was_enabled = bool(CC.enabled)

  advance_to(end_ns + 200_000_000)
  if proxy.active or proxy.arm_pending:
    proxy.set_control(False, False, 0.0)
    drain_echo()

  print('RESULT active', proxy.active, 'freshness_ready', proxy.freshness_ready,
        'arms', stats['arm'], 'releases', stats['release'],
        'host_08a_accepted', stats['host_08a_accepted'], 'last_failure', proxy.last_failure_reason)
  print('enabled_windows', enabled_windows, 'active_windows', active_windows,
        'active_native', strict_active_native, 'host_id11', strict_host_id11,
        'blocked', native_blocked, 'leaked', native_leaked, 'safety_invalid', safety_invalid)
  print('stats', stats)
  for f in failures[:100]:
    print('FAIL', f)

  if args.drop_sign_response is not None:
    assert drop_exercised, f'did not reach sign generation {args.drop_sign_response}'
  assert proxy.last_failure_reason == '', proxy.last_failure_reason
  assert stats['arm'] == stats['release'] == enabled_windows, (stats['arm'], stats['release'], enabled_windows)
  assert stats['arm'] > 0
  assert strict_host_id11 > 100
  assert native_leaked == 0
  assert not safety_invalid
  assert not failures, failures[:20]
  unexpected_rejects = sum(v for k, v in stats.items() if isinstance(k, tuple) and len(k) >= 3 and k[0] == 'host_tx' and k[2] == 'R')
  unexpected_rejects -= stats['expected_controls_disallowed_08a_reject']
  assert unexpected_rejects == 0, unexpected_rejects
  print('PASS F33 FULL ROUTE REPLAY')
