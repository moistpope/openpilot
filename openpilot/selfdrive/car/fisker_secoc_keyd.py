#!/usr/bin/env python3
"""Fisker Ocean SecOC key-recovery daemon.

The Ocean protects its ADAS control frames (ADAS_STEER_CONTROL 0x1D0, ADAS_ACCEL_CONTROL 0x121)
with AUTOSAR SecOC: a truncated AES-128-CMAC keyed by a per-vehicle 16-byte symmetric key. openpilot
cannot sign (and therefore cannot steer/accelerate) without that key, and no universal key exists --
each car needs its own key recovered at runtime. See opendbc/car/fisker_secoc.py for the MAC
construction and opendbc/car/fisker/README.md for the wider port status.

Recovery reads the key material back over UDS. The key is stored per-ECU under DID 0xEFF5
("SecOC symmetric access value") and can be read from the radar modules, which -- unlike the BCM/BMS
that also hold it -- answer a plain ReadDataByIdentifier without a signed security-access unlock.
We query all five radars and only accept a key that at least three of them agree on, which guards
against a wrong/partial read on any single module.

Bus topology (Comma Four deployment):
  * can0  -- car bus. openpilot impersonates the stock ADAS/Hydra module here (control TX).
  * can2  -- the isolated stock ADAS/Hydra module, behind the intercept relay.
  * can1  -- the vehicle diagnostic bus, exposed in OBD-II multiplex mode. UDS runs here, so this
             daemon enables OBD multiplexing and queries on DIAG_BUS below.

The daemon self-gates on brand == "fisker" and secOcRequired, exits as soon as a valid key is
already stored, and otherwise retries every RETRY_PERIOD seconds. On success it writes the key to
the SecOCKey param (consumed by selfdrive/car/card.py) and to /cache/params/SecOCKey so it survives
across param resets.
"""
import os
import time

import openpilot.cereal.messaging as messaging
from opendbc.car.structs import car
from opendbc.car.can_definitions import CanData
from opendbc.car.isotp_parallel_query import IsoTpParallelQuery
from openpilot.common.params import Params
from openpilot.common.swaglog import cloudlog

# Radar modules that hold a readable copy of the SecOC key (UDS request addresses, see the ECU
# inventory in the knowledge base / _reference/ecus.json): MRR, CMRR_FR, CMRR_FL, CMRR_RL, CMRR_RR.
RADAR_ADDRS = [0x781, 0x782, 0x794, 0x796, 0x7A7]

# UDS DID 0xEFF5 = "SecOC symmetric key / access value".
SECOC_KEY_DID = 0xEFF5
RDBI_REQUEST = bytes([0x22]) + SECOC_KEY_DID.to_bytes(2, "big")
RDBI_RESPONSE = bytes([0x62]) + SECOC_KEY_DID.to_bytes(2, "big")

# Session-control / tester-present prefixes. Some radars reject the read in the default session with
# NRC 0x33 (securityAccessDenied), so we retry the same read behind a tester-present frame and then
# behind an extended-session switch.
TESTER_PRESENT_REQUEST = bytes([0x3E, 0x00])
TESTER_PRESENT_RESPONSE = bytes([0x7E, 0x00])
EXT_SESSION_REQUEST = bytes([0x10, 0x03])
EXT_SESSION_RESPONSE = bytes([0x50, 0x03])

# (request list, response list) tried in order per module until one returns key material.
SESSION_PROFILES = [
  ([RDBI_REQUEST], [RDBI_RESPONSE]),
  ([TESTER_PRESENT_REQUEST, RDBI_REQUEST], [TESTER_PRESENT_RESPONSE, RDBI_RESPONSE]),
  ([EXT_SESSION_REQUEST, RDBI_REQUEST], [EXT_SESSION_RESPONSE, RDBI_RESPONSE]),
]

# Comma Four: the vehicle diagnostic bus sits on can1 in OBD-II multiplex mode.
DIAG_BUS = 1

KEY_LEN = 16
# Majority of the five radar modules must return the identical 16-byte value.
CONSENSUS = (len(RADAR_ADDRS) // 2) + 1

RETRY_PERIOD = 30.0
QUERY_TIMEOUT = 0.2

SECOC_KEY_CACHE_PATH = "/cache/params/SecOCKey"


def extract_key_candidates(data: bytes) -> list[bytes]:
  """Pull 16-byte key candidates out of a raw DID response payload.

  Different modules return the material differently: some give exactly the 16 raw bytes, some pad or
  prefix it, and some return it as a 32-character ASCII-hex *string*. Try every plausible reading.
  """
  candidates: list[bytes] = []
  if len(data) == KEY_LEN:
    candidates.append(data)
  elif len(data) > KEY_LEN:
    candidates.append(data[:KEY_LEN])
    candidates.append(data[-KEY_LEN:])
    if len(data) == 2 * KEY_LEN:
      try:
        candidates.append(bytes.fromhex(data.decode("ascii")))
      except (ValueError, UnicodeDecodeError):
        pass
  # De-dupe while preserving order, and drop anything that isn't exactly 16 bytes.
  seen: set[bytes] = set()
  out: list[bytes] = []
  for c in candidates:
    if len(c) == KEY_LEN and c not in seen:
      seen.add(c)
      out.append(c)
  return out


def consensus_key(module_candidates: dict[int, list[bytes]]) -> bytes | None:
  """Return a 16-byte key returned by at least CONSENSUS distinct modules, else None."""
  votes: dict[bytes, set[int]] = {}
  for addr, cands in module_candidates.items():
    # count each candidate value at most once per module
    for value in set(cands):
      votes.setdefault(value, set()).add(addr)

  best: bytes | None = None
  best_count = 0
  for value, modules in votes.items():
    if len(modules) > best_count:
      best, best_count = value, len(modules)

  if best is not None and best_count >= CONSENSUS:
    return best
  return None


def make_can_callbacks(logcan: messaging.SubSocket, sendcan: messaging.PubSocket):
  from openpilot.selfdrive.pandad import can_list_to_can_capnp

  def can_recv(wait_for_one: bool = False) -> list[list[CanData]]:
    ret = []
    for can in messaging.drain_sock(logcan, wait_for_one=wait_for_one):
      ret.append([CanData(msg.address, msg.dat, msg.src) for msg in can.can])
    return ret

  def can_send(msgs: list[CanData]) -> None:
    sendcan.send(can_list_to_can_capnp(msgs, msgtype='sendcan'))

  return can_recv, can_send


def query_module_key(can_recv, can_send, addr: int) -> list[bytes]:
  """Try each session profile against one radar until one yields key candidates."""
  for request, response in SESSION_PROFILES:
    try:
      query = IsoTpParallelQuery(can_send, can_recv, DIAG_BUS, [addr], request, response)
      results = query.get_data(QUERY_TIMEOUT)
    except Exception:
      cloudlog.exception(f"fisker_secoc_keyd query error addr=0x{addr:03X}")
      continue

    data = results.get(addr)
    if data:
      candidates = extract_key_candidates(bytes(data))
      if candidates:
        cloudlog.warning(f"fisker_secoc_keyd addr=0x{addr:03X} returned {len(candidates)} key candidate(s)")
        return candidates
  return []


def store_key(params: Params, key: bytes) -> None:
  key_hex = key.hex()
  params.put("SecOCKey", key_hex, block=True)
  try:
    os.makedirs(os.path.dirname(SECOC_KEY_CACHE_PATH), exist_ok=True)
    with open(SECOC_KEY_CACHE_PATH, "w") as f:
      f.write(key_hex)
  except OSError:
    cloudlog.exception("fisker_secoc_keyd failed to persist key to cache")
  cloudlog.warning("fisker_secoc_keyd stored recovered SecOC key")


def have_valid_key(params: Params) -> bool:
  stored = params.get("SecOCKey")
  if stored is None:
    return False
  try:
    return len(bytes.fromhex(stored.strip())) == KEY_LEN
  except ValueError:
    return False


def set_obd_multiplexing(params: Params, enabled: bool) -> None:
  """Route the diagnostic bus to the OBD-II connector via pandad (same mechanism card.py uses)."""
  if params.get_bool("ObdMultiplexingEnabled") != enabled:
    cloudlog.warning(f"fisker_secoc_keyd setting OBD multiplexing to {enabled}")
    params.remove("ObdMultiplexingChanged")
    params.put_bool("ObdMultiplexingEnabled", enabled, block=True)
    params.get_bool("ObdMultiplexingChanged", block=True)


def main() -> None:
  params = Params()

  CP = messaging.log_from_bytes(params.get("CarParams", block=True), car.CarParams)
  if CP.brand != "fisker" or not CP.secOcRequired:
    cloudlog.warning("fisker_secoc_keyd not needed for this car, exiting")
    return

  if have_valid_key(params):
    cloudlog.warning("fisker_secoc_keyd valid SecOC key already stored, exiting")
    return

  logcan = messaging.sub_sock('can', timeout=100)
  sendcan = messaging.pub_sock('sendcan')
  can_recv, can_send = make_can_callbacks(logcan, sendcan)

  # Give sockets a moment to connect before the first query.
  time.sleep(0.5)

  obd_enabled = False
  try:
    while not have_valid_key(params):
      if not obd_enabled:
        set_obd_multiplexing(params, True)
        obd_enabled = True

      module_candidates: dict[int, list[bytes]] = {}
      for addr in RADAR_ADDRS:
        candidates = query_module_key(can_recv, can_send, addr)
        if candidates:
          module_candidates[addr] = candidates

      key = consensus_key(module_candidates)
      if key is not None:
        store_key(params, key)
        break

      responded = len(module_candidates)
      cloudlog.warning(f"fisker_secoc_keyd no consensus ({responded}/{len(RADAR_ADDRS)} modules responded, "
                       f"need {CONSENSUS} agreeing), retrying in {RETRY_PERIOD:.0f}s")
      time.sleep(RETRY_PERIOD)
  finally:
    # Hand the diagnostic bus back so it doesn't interfere with the control path.
    if obd_enabled:
      try:
        set_obd_multiplexing(params, False)
      except Exception:
        cloudlog.exception("fisker_secoc_keyd failed to restore OBD multiplexing")

  # Key is recovered. Stay alive until the manager stops us (the fisker_secoc process gate drops
  # once the key is stored) so the process monitor never sees us as "shouldBeRunning but not running"
  # in the window between finishing and being stopped. The "already stored" early-return above still
  # exits immediately, which is what a manual invocation wants.
  cloudlog.warning("fisker_secoc_keyd key available, idling until stopped")
  while True:
    time.sleep(60)


if __name__ == "__main__":
  main()
