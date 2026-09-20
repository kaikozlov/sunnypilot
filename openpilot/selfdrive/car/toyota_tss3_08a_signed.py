"""Exact-F33 authenticated 0x08A request-plane replacement.

The FRC supplies each source generation and all Toyota-owned request fields.
Openpilot selectively replaces its lateral and/or ordinary DRCC acceleration
fields on that same source generation, and the EPS RAM resident signs the
modified application. No future-generation prediction or host SecOC key is used.
"""
from __future__ import annotations

import struct
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.tss3 import (
  TSS3_LATERAL_SOURCE_IDS,
  build_request_application,
  target_angle_deg_to_raw,
)
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.common.swaglog import cloudlog

NATIVE_08A_ADDR = 0x08A
SECOC_SYNC_ADDR = 0x00F
ADMIN_ADDR = 0x777
UPSTREAM_BUS = 2
SYNC_BUS = 0
DOWNSTREAM_BUS = 0
ADMIN_BUS = 1
PANDA_RETURNED_OFFSET = 0x80
PANDA_REJECTED_OFFSET = 0xC0
SendCan = Callable[[list[CanData]], None]
ButtonType = structs.CarState.ButtonEvent.Type

ORACLE_REQUEST_ADDR = 0x1FDC0002
ORACLE_RESPONSE_ADDR = 0x1FE00002
ORACLE_BUS = 0
ORACLE_PRIVATE_SID = 0xC9
ORACLE_SEQUENCE_MAX = 0x1F
# Parked raw-classic qualification: 100/100 at 25 ms cadence, p99 25.49 ms,
# max 36.27 ms. A missing response is not authority loss: retry the same source
# generation after 50 ms, and only declare the signer dead after Panda's existing
# 100 ms replacement watchdog has already had time to fail open.
ORACLE_RETRY_TIMEOUT_S = 0.050
ORACLE_DEAD_TIMEOUT_S = 0.120

def decode_sync(data: bytes) -> tuple[int, int]:
  if len(data) != 8:
    raise ValueError("0x00F sync frame must be 8 bytes")
  trip = int.from_bytes(data[0:2], "big")
  reset = (data[2] << 12) | (data[3] << 4) | (data[4] >> 4)
  return trip, reset


def make_admin(arm: bool) -> CanData:
  return CanData(ADMIN_ADDR, bytes((7, 0xC9, 0xA8, int(arm), 0, 0, 0, 0)), ADMIN_BUS)


def request_plane_enabled(CP: structs.CarParams) -> bool:
  return (CP.carFingerprint == CAR.TOYOTA_CAMRY_TSS3 and not CP.passive and bool(CP.safetyConfigs) and
          bool(CP.safetyConfigs[0].safetyParam & ToyotaSafetyFlags.TSS3_08A_HOST.value))


def shift_reset_epoch(trip_counter: int, reset_counter: int, delta: int) -> tuple[int, int]:
  packed = (((trip_counter << 20) | reset_counter) + delta) & ((1 << 36) - 1)
  return packed >> 20, packed & ((1 << 20) - 1)


def resolve_epoch(sync_trip: int, sync_reset: int, reset_low2: int) -> tuple[int, int] | None:
  # 0x00F and 0x08A can straddle the same reset transition. Native FV4 selects
  # the generation; 0x00F only supplies the nearby full reset/trip value.
  for delta in (0, -1, 1, -2, 2):
    trip, reset = shift_reset_epoch(sync_trip, sync_reset, delta)
    if (reset & 0x3) == reset_low2:
      return trip, reset
  return None


def build_secoc_domain(application: bytes, trip_counter: int, reset_counter: int, message_counter: int) -> bytes:
  if len(application) != 28:
    raise ValueError("0x08A application must be 28 bytes")
  freshness = struct.pack(">HI", trip_counter,
                          (reset_counter << 12) | (message_counter << 4) | ((reset_counter & 0x3) << 2))
  return b"\x00\x8A" + application + freshness


def build_oracle_transport(seq: int, application: bytes, message_counter: int, reset_counter: int) -> list[CanData]:
  """Build one stateless raw-classic signer transaction.

  Four fragments carry the exact 28 application bytes. The fifth carries only
  freshness metadata and a fixed trailer. All five are submitted together; the
  EPS resident reads them from the pre-staging RX ring, so there is no ISO-TP
  flow-control or receiver-paced transport state.
  """
  if not 1 <= seq <= ORACLE_SEQUENCE_MAX:
    raise ValueError(f"oracle sequence must be 1..{ORACLE_SEQUENCE_MAX}")
  if len(application) != 28:
    raise ValueError("oracle application must be exactly 28 bytes")
  if not 0 <= message_counter <= 0xFF:
    raise ValueError("oracle message counter must fit u8")

  frames = []
  for fragment in range(4):
    header = (fragment << 5) | seq
    frames.append(CanData(ORACLE_REQUEST_ADDR,
                          bytes((header,)) + application[fragment * 7:(fragment + 1) * 7],
                          ORACLE_BUS))
  frames.append(CanData(ORACLE_REQUEST_ADDR,
                        bytes(((4 << 5) | seq, message_counter, reset_counter & 0xFF,
                               ORACLE_PRIVATE_SID, 0xA8, seq ^ 0xFF, 0x5A, 0xA5)),
                        ORACLE_BUS))
  return frames


def build_signed_frame(application: bytes, reset_counter: int, message_counter: int, cmac4: bytes) -> bytes:
  if len(application) != 28 or len(cmac4) != 4:
    raise ValueError("invalid signed-frame geometry")
  fv4 = ((message_counter & 0x3) << 2) | (reset_counter & 0x3)
  mac28 = int.from_bytes(cmac4, "big") >> 4
  return application + ((fv4 << 28) | mac28).to_bytes(4, "big")


def build_id11_application(native_application: bytes, target_angle_raw: int) -> bytes:
  """Compatibility wrapper for lateral-only analysis and tests."""
  return build_request_application(native_application, lat_active=True, target_angle_raw=target_angle_raw,
                                   long_control=False, accel=0.0)


@dataclass(frozen=True)
class NativeEvent:
  index: int
  frame: bytes
  application: bytes
  b26: int
  trip_counter: int
  reset_counter: int
  message_low2: int

  @property
  def target_id(self) -> int:
    return self.application[21] & 0x3F


class NativeFreshnessTracker:
  """Recover freshness passively at a native reset boundary, then track +1."""

  def __init__(self) -> None:
    self.event: NativeEvent | None = None
    self.message_counter: int | None = None

  @property
  def ready(self) -> bool:
    return self.message_counter is not None

  def reset(self) -> None:
    self.event = None
    self.message_counter = None

  def update(self, event: NativeEvent) -> tuple[bool, bool]:
    """Return (ready, lost_ready_state).

    Native F33 starts each reset epoch at message counter 1 and advances B26 by
    one per publication. Waiting for the next observed epoch boundary therefore
    removes the need to brute-force the hidden high message-counter bits.
    """
    prev = self.event
    was_ready = self.ready
    self.event = event
    if prev is None:
      return False, False

    if ((event.b26 - prev.b26) & 0x3F) != 1:
      self.message_counter = None
      return False, was_ready

    reset_changed = (event.trip_counter, event.reset_counter) != (prev.trip_counter, prev.reset_counter)
    if not was_ready:
      if reset_changed and event.message_low2 == 1:
        self.message_counter = 1
        return True, False
      return False, False

    if reset_changed:
      if event.message_low2 != 1:
        self.message_counter = None
        return False, True
      self.message_counter = 1
      return True, False

    message_counter = (int(self.message_counter) + 1) & 0xFF
    if (message_counter & 0x3) != event.message_low2:
      self.message_counter = None
      return False, True
    self.message_counter = message_counter
    return True, False


@dataclass
class SignJob:
  native_index: int
  application: bytes
  reset_counter: int
  message_counter: int
  first_sent_at: float | None = None
  sent_at: float | None = None
  attempts: int = 0


class ToyotaTss3RequestProxy:
  """Minimal asynchronous signer/forwarding adapter for exact-F33 0x08A."""

  def __init__(self, send_can: SendCan, *, start_thread: bool = True, monotonic=time.monotonic):
    self._send_can = send_can
    self._monotonic = monotonic
    self._cv = threading.Condition(threading.RLock())
    self._stop = False
    self._thread: threading.Thread | None = None

    self.can_valid = False
    self.control_enabled = False
    self.control_lat_active = False
    self.control_target_angle_raw = 0
    self.control_long_enabled = False
    self.control_long_active = False
    self.control_accel = 0.0
    self.sync_trip: int | None = None
    self.sync_reset: int | None = None
    self.native_index = 0
    self.tracker = NativeFreshnessTracker()

    self.jobs: deque[SignJob] = deque()
    self.inflight: dict[int, SignJob] = {}
    self.next_oracle_seq = 1

    self.active = False
    self.arm_pending = False
    self.arm_clone_frame: bytes | None = None
    self.handoff_completed = False
    self.pending_outputs: dict[int, bytes | None] = {}
    self.next_output_index: int | None = None

    self.last_failure_reason = ""

    if start_thread:
      self._thread = threading.Thread(target=self._oracle_sender_loop, name="tss3_08a_oracle", daemon=True)
      self._thread.start()

  @property
  def freshness_ready(self) -> bool:
    return self.tracker.ready

  def set_control(self, enabled: bool, lat_active: bool, target_angle_deg: float,
                  long_enabled: bool = False, long_active: bool = False, accel: float = 0.0) -> None:
    with self._cv:
      was_enabled = self.control_enabled
      self.control_enabled = bool(enabled)
      self.control_lat_active = self.control_enabled and bool(lat_active)
      self.control_target_angle_raw = target_angle_deg_to_raw(float(target_angle_deg))
      self.control_long_enabled = self.control_enabled and bool(long_enabled)
      self.control_long_active = self.control_long_enabled and bool(long_active)
      self.control_accel = float(accel) if self.control_long_active else 0.0
      if was_enabled and not self.control_enabled:
        self._release_control_locked()
      elif not was_enabled and self.control_enabled:
        self._maybe_arm_locked()

  def consume_handoff_completed(self) -> bool:
    with self._cv:
      completed = self.handoff_completed
      self.handoff_completed = False
      return completed

  def authority_unavailable(self) -> bool:
    with self._cv:
      # The one-generation atomic handoff is expected and should not surface as
      # a steering-unavailable warning. A failed handoff clears arm_pending and
      # is reported normally on the next state update.
      return self.control_enabled and not self.active and not self.arm_pending

  def longitudinal_authority_unavailable(self) -> bool:
    with self._cv:
      return self.control_long_enabled and not self.active and not self.arm_pending

  def _record_failure_locked(self, reason: str) -> None:
    self.last_failure_reason = reason
    cloudlog.event("toyota_f33_request_plane_failure", reason=reason, active=self.active,
                   arm_pending=self.arm_pending, freshness_ready=self.tracker.ready,
                   native_index=self.native_index, error=True)

  def _invalidate_signing_locked(self) -> None:
    self.jobs.clear()
    self.inflight.clear()
    self.pending_outputs.clear()
    self.next_output_index = None
    self._cv.notify_all()

  def _release_locked(self) -> None:
    if self.active or self.arm_pending:
      self._send_can([make_admin(False)])
    self.active = False
    self.arm_pending = False
    self.arm_clone_frame = None
    self.handoff_completed = False

  def _release_control_locked(self) -> None:
    self._release_locked()
    self._invalidate_signing_locked()

  def _authority_failure_locked(self, reason: str) -> None:
    self._record_failure_locked(reason)
    self._release_control_locked()

  def _maybe_arm_locked(self) -> None:
    if self.active or self.arm_pending or not self.control_enabled or not self.tracker.ready or not self.can_valid:
      return
    self._send_can([make_admin(True)])
    self.arm_pending = True
    self.arm_clone_frame = None

  def _make_native_event_locked(self, frame: bytes) -> NativeEvent | None:
    if len(frame) != 32 or self.sync_trip is None or self.sync_reset is None:
      return None
    fv4 = frame[28] >> 4
    epoch = resolve_epoch(self.sync_trip, self.sync_reset, fv4 & 0x3)
    if epoch is None:
      return None
    self.native_index += 1
    return NativeEvent(self.native_index, frame, frame[:28], frame[26] & 0x3F,
                       epoch[0], epoch[1], (fv4 >> 2) & 0x3)

  def _observe_sync_locked(self, data: bytes) -> None:
    try:
      self.sync_trip, self.sync_reset = decode_sync(data)
    except ValueError:
      pass

  def _queue_sign_locked(self, event: NativeEvent) -> None:
    if self.control_lat_active and event.target_id not in TSS3_LATERAL_SOURCE_IDS:
      self._authority_failure_locked("unsupported_native_lateral_id")
      return
    message_counter = self.tracker.message_counter
    if message_counter is None:
      self._authority_failure_locked("freshness_not_ready")
      return
    application = build_request_application(
      event.application,
      lat_active=self.control_lat_active,
      target_angle_raw=self.control_target_angle_raw,
      long_control=self.control_long_enabled,
      accel=self.control_accel,
    )
    if self.next_output_index is None:
      self.next_output_index = event.index
    self.pending_outputs[event.index] = None
    self.jobs.append(SignJob(event.index, application, event.reset_counter, message_counter))
    self._cv.notify_all()

  def _observe_native_locked(self, frame: bytes) -> None:
    event = self._make_native_event_locked(frame)
    if event is None or not self.can_valid:
      if self.control_enabled or self.active or self.arm_pending:
        self._authority_failure_locked("native_event_invalid")
      self.tracker.reset()
      return

    ready, lost = self.tracker.update(event)
    if lost:
      if self.control_enabled or self.active or self.arm_pending:
        self._record_failure_locked("freshness_lost")
      self._release_control_locked()
      return

    if not ready:
      return

    if self.arm_pending:
      if self.arm_clone_frame is not None:
        self._authority_failure_locked("handoff_source_overrun")
        return
      self.arm_clone_frame = event.frame
      self.next_output_index = event.index + 1
      self._send_can([CanData(NATIVE_08A_ADDR, event.frame, DOWNSTREAM_BUS)])
    elif self.active:
      self._queue_sign_locked(event)

    self._maybe_arm_locked()

  def _observe_tx_echo_locked(self, address: int, data: bytes, src: int,
                              gas_pressed: bool, brake_pressed: bool, cancel_pressed: bool,
                              cruise_disengaged: bool) -> None:
    if address == ADMIN_ADDR and self.arm_pending and data == make_admin(True).dat:
      if src == ADMIN_BUS + PANDA_REJECTED_OFFSET:
        self._authority_failure_locked("arm_admin_rejected")
      return
    if address != NATIVE_08A_ADDR:
      return
    if src == DOWNSTREAM_BUS + PANDA_RETURNED_OFFSET and self.arm_pending and data == self.arm_clone_frame:
      self.active = True
      self.arm_pending = False
      self.handoff_completed = True
      self.arm_clone_frame = None
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.arm_pending and data == self.arm_clone_frame:
      self._authority_failure_locked("handoff_clone_rejected")
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.active:
      # Panda can observe a pedal, cancel, or native PCM disengagement before
      # card publishes the corresponding inactive/release command. A rejected
      # command already queued across that edge is an ordinary TX safety
      # outcome, not lost authority.
      if not gas_pressed and not brake_pressed and not cancel_pressed and not cruise_disengaged:
        cloudlog.event("toyota_f33_request_plane_tx_reject", native_index=self.native_index, error=True)
        self._release_control_locked()

  def _flush_outputs_locked(self) -> None:
    if self.next_output_index is None:
      return
    out = []
    while self.next_output_index in self.pending_outputs and self.pending_outputs[self.next_output_index] is not None:
      out.append(CanData(NATIVE_08A_ADDR, self.pending_outputs.pop(self.next_output_index), DOWNSTREAM_BUS))
      self.next_output_index += 1
    if out:
      self._send_can(out)

  def _retry_job_locked(self, seq: int, job: SignJob, now: float, reason: str) -> None:
    self.inflight.pop(seq, None)
    if job.native_index not in self.pending_outputs:
      return
    if job.first_sent_at is not None and now - job.first_sent_at > ORACLE_DEAD_TIMEOUT_S:
      self._authority_failure_locked("oracle_dead")
      return
    job.sent_at = None
    self.jobs.appendleft(job)
    cloudlog.event("toyota_f33_request_plane_retry", reason=reason, native_index=job.native_index,
                   attempts=job.attempts)
    self._cv.notify_all()

  def _retry_blocking_job_locked(self, now: float, reason: str, *, force: bool = False) -> None:
    if self.next_output_index is None:
      return

    # Only the oldest unsigned source generation can stall downstream output.
    # Newer responses may remain buffered without affecting authority.
    for seq, job in tuple(self.inflight.items()):
      if job.native_index != self.next_output_index:
        continue
      if job.first_sent_at is not None and now - job.first_sent_at > ORACLE_DEAD_TIMEOUT_S:
        self._authority_failure_locked("oracle_dead")
      elif force or (job.sent_at is not None and now - job.sent_at > ORACLE_RETRY_TIMEOUT_S):
        self._retry_job_locked(seq, job, now, reason)
      return

    # A blocking generation may already be queued for retry. It is still the
    # same authority generation; only declare it dead after the hard deadline.
    for job in self.jobs:
      if job.native_index == self.next_output_index:
        if job.first_sent_at is not None and now - job.first_sent_at > ORACLE_DEAD_TIMEOUT_S:
          self._authority_failure_locked("oracle_dead")
        return

  def _observe_oracle_response_locked(self, data: bytes) -> None:
    if len(data) != 8 or data[0] != ORACLE_PRIVATE_SID:
      return
    seq, status = data[1], data[2]
    if not 1 <= seq <= ORACLE_SEQUENCE_MAX or data[3] != (seq ^ 0xFF):
      return
    job = self.inflight.get(seq)
    if job is None:
      return
    now = self._monotonic()
    if status != 0:
      self._retry_job_locked(seq, job, now, "oracle_sign_status")
      return
    self.inflight.pop(seq, None)
    if job.native_index not in self.pending_outputs:
      return
    self.pending_outputs[job.native_index] = build_signed_frame(job.application, job.reset_counter, job.message_counter, data[4:8])

    # On one CAN bus, observing a later generation's reply while the oldest
    # generation is still unanswered is direct evidence that the older reply was
    # lost. Retry that same source generation immediately instead of releasing.
    if self.next_output_index is not None and job.native_index > self.next_output_index:
      self._retry_blocking_job_locked(now, "later_oracle_response", force=True)
    self._flush_outputs_locked()
    self._cv.notify_all()

  def _alloc_seq_locked(self) -> int:
    used = set(self.inflight)
    for _ in range(ORACLE_SEQUENCE_MAX):
      seq = self.next_oracle_seq
      self.next_oracle_seq = (seq % ORACLE_SEQUENCE_MAX) + 1
      if seq not in used:
        return seq
    raise RuntimeError("oracle sequence space exhausted")

  def _expire_locked(self, now: float) -> None:
    self._retry_blocking_job_locked(now, "oracle_response_timeout")

  def _next_job_locked(self, now: float) -> tuple[int, SignJob] | None:
    self._expire_locked(now)
    if not self.jobs:
      return None
    job = self.jobs.popleft()
    seq = self._alloc_seq_locked()
    if job.first_sent_at is None:
      job.first_sent_at = now
    job.sent_at = now
    job.attempts += 1
    self.inflight[seq] = job
    return seq, job

  def _oracle_sender_loop(self) -> None:
    while True:
      with self._cv:
        if self._stop:
          return
        item = self._next_job_locked(self._monotonic())
        if item is None:
          self._cv.wait(timeout=0.002)
          continue
      seq, job = item
      self._send_can(build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter))

  def update(self, can_list: list, CS: structs.CarState) -> None:
    with self._cv:
      self.can_valid = bool(CS.canValid)
      gas_pressed = bool(getattr(CS, "gasPressed", False))
      brake_pressed = bool(getattr(CS, "brakePressed", False))
      cancel_pressed = any(button.type == ButtonType.cancel and button.pressed
                           for button in getattr(CS, "buttonEvents", ()))
      cruise_state = getattr(CS, "cruiseState", None)
      cruise_disengaged = cruise_state is not None and not bool(cruise_state.enabled)
      if not self.can_valid and (self.active or self.arm_pending):
        self._authority_failure_locked("can_invalid")
        self.tracker.reset()
      for _, packets in can_list:
        for address, dat, src in packets:
          address_i, src_i, data = int(address), int(src), bytes(dat)
          if src_i >= PANDA_RETURNED_OFFSET:
            self._observe_tx_echo_locked(address_i, data, src_i, gas_pressed, brake_pressed,
                                         cancel_pressed, cruise_disengaged)
          elif src_i == SYNC_BUS and address_i == SECOC_SYNC_ADDR:
            self._observe_sync_locked(data)
          elif src_i == UPSTREAM_BUS and address_i == NATIVE_08A_ADDR:
            self._observe_native_locked(data)
          elif src_i == ORACLE_BUS and address_i == ORACLE_RESPONSE_ADDR:
            self._observe_oracle_response_locked(data)
      self._cv.notify_all()

  def shutdown(self) -> None:
    with self._cv:
      self._release_locked()
      self._stop = True
      self._cv.notify_all()
    if self._thread is not None:
      self._thread.join(timeout=1.0)
