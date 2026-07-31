# Fisker Ocean — Comma Four integration (openpilot side)

This documents the openpilot-repo wiring for running the Fisker Ocean port on a **Comma Four**. The
car port itself (interface / carstate / carcontroller / DBC / SecOC math) lives in the `opendbc_repo`
submodule (`opendbc/car/fisker/`, `opendbc/car/fisker_secoc.py`). This file only covers what the
openpilot repository adds on top of it.

## Bus topology (this vehicle's harness)

The ADAS bus is split at the stock ADAS/Hydra module's connector via a Comma intercept relay:

| Panda bus | Wire | Carries |
|-----------|------|---------|
| `can0` | car side | The car bus — EPS, VCU, BCM, ESP, etc. openpilot **impersonates the ADAS/Hydra module here**, so all control TX (`ADAS_STEER_CONTROL` 0x1D0, `ADAS_ACCEL_CONTROL` 0x121, `LKAS_STEER_AUTHORITY` 0x1C0) goes out on bus 0. `GW_SECOC_SYNC` (0x20) is also read here. |
| `can2` | ADAS side | The isolated stock ADAS/Hydra computer, behind the relay. |
| `can1` | diagnostic | The vehicle diagnostic bus, exposed in **OBD-II multiplex mode**. All UDS request/response traffic runs here. |

The port already emits its control frames on bus 0 (see `opendbc/car/fisker/fiskercan.py`), so no
change was needed there for this harness. The one place openpilot must talk to the diagnostic bus is
SecOC key recovery, below.

## What this adds

### 1. opendbc submodule pointer

The previous `opendbc_repo` gitlink referenced a commit that does not exist on the `moistpope/opendbc`
remote, so `git submodule update` could not check it out and the Fisker port was unreachable. It is
now repointed at the `moistpope/opendbc` branch `claude/fisker-ocean-openpilot-voq00l`, which carries
the Fisker port plus the full lateral takeover (0x1C0 authority frame + SecOC/ARC counter seeding,
see below). After checking out this branch:

```
git submodule update --init opendbc_repo
```

### 2. SecOC key-recovery daemon — `fisker_secoc_keyd.py`

The Ocean signs its ADAS control frames with AUTOSAR SecOC (a truncated AES-128-CMAC keyed by a
per-vehicle 16-byte key). openpilot cannot steer or accelerate without that key, and there is no
universal key — each car's key must be recovered at runtime.

`openpilot/selfdrive/car/fisker_secoc_keyd.py`:

- Self-gates on `CarParams.brand == "fisker"` and `secOcRequired`, and exits immediately if a valid
  `SecOCKey` is already stored.
- Enables OBD multiplexing (so `can1` is the diagnostic bus) and queries UDS **DID `0xEFF5`**
  ("SecOC symmetric access value") on the five radar modules — MRR `0x781`, CMRR_FR `0x782`,
  CMRR_FL `0x794`, CMRR_RL `0x796`, CMRR_RR `0x7A7` — over `DIAG_BUS = 1`.
- Retries each module through three session profiles (default → tester-present → extended session),
  because some radars reject the read in the default session with NRC `0x33`.
- Extracts 16-byte key candidates (raw-16, first-16/last-16, or ASCII-hex-decoded from a 32-char
  string) and accepts a key only if **≥3 of the 5** modules agree on the identical value. On
  disagreement it stores nothing and retries every 30 s.
- On success, writes the key to the `SecOCKey` param and to `/cache/params/SecOCKey`, then restores
  OBD multiplexing to off so the diagnostic bus does not interfere with the control path.

The recovered key is consumed by the existing generic SecOC plumbing in
`openpilot/selfdrive/car/card.py`, which loads `SecOCKey` into `CI.CS.secoc_key` / `CI.CC.secoc_key`.

### 3. Process registration

`fisker_secoc_keyd` is registered in `openpilot/system/manager/process_config.py` behind a
`fisker_secoc` gate (`started and brand == "fisker" and secOcRequired`).

## Lateral control takeover (opendbc side)

The steering takeover lives in the `opendbc_repo` submodule (`opendbc/car/fisker/`). Two things are
required for the EPS to accept openpilot's steering, and both are now implemented:

- **`LKAS_STEER_AUTHORITY` (0x1C0)** is generated alongside `ADAS_STEER_CONTROL` (0x1D0) whenever
  lateral control is active. It is non-SecOC (CRC over bytes 1-7, xor-out 0x03, its own ARC) and
  carries the lateral-control validity fields, all set valid. Without it the EPS raises
  `U12F786`/`U12F787` and ignores the steer command.
- **Seamless counter continuation.** `secoc_mirror.py` continuously reconstructs the stock Hydra
  module's full SecOC running message counter (the way the receiver does, past the 6-bit wire wrap)
  and the byte-1 ARC, per message and per `GW_SECOC_SYNC` reset epoch. At the takeover rising edge
  the controller seeds its counters from the mirror (`running + 1`, next ARC) so there is no
  discontinuity for the EPS to reject; counters restart at 1 on each new reset epoch.

## Panda safety mode — `SAFETY_FISKER`

The port now runs under `SafetyModel.fisker` (`opendbc/safety/modes/fisker.h`), which enforces the
lateral limits in firmware:

- **Steering** (`0x1D0`): absolute torque cap (±192), per-frame rate limits, a 250 ms real-time
  rate bound, driver-torque blending (`TorqueDriverLimited`), and zero torque unless
  `controls_allowed`.
- **Authority** (`0x1C0`): allowlisted (carries no actuation).
- **Longitudinal** (`0x121`): blocked unless the `LONGITUDINAL` safety flag is set (it is not, since
  openpilot longitudinal is off); when enabled it is accel-limited.
- Engagement follows the stock ACC (`pcm_cruise`), with brake/gas/speed monitored from the car bus,
  and the stock module's control addresses are blocked from being forwarded across the relay.

The enforced steering/accel **limits are still provisional placeholders**, and the driver-torque
calibration is unverified, so this remains **bench / closed-course bring-up only** until they are
tuned against real data.
