#!/usr/bin/env python3
"""
ics_physics_sentinel.py: SCADA false-data detector based on plant physics.

Runs with Python 3 only. No packages or network needed.

Malware like Stuxnet sends normal-looking sensor values to the control room
while the real machine runs outside safe limits. This script decodes Modbus/TCP
frames and checks whether the reported values could happen together. Each
value can be within its own limit while the combination is impossible, for
example a turbine near rated speed reporting a bearing at room temperature.

Machine modelled: a 2-pole synchronous generator on India's 50 Hz grid.
  * Synchronous speed = 120 * f / p = 120 * 50 / 2 = 3000 RPM.
  * Overspeed trip at about 110% of rated speed = 3300 RPM.
  * Grid frequency band 49.90 to 50.05 Hz (IEGC 2023, nominal 50.000 Hz).
    Relay trip settings are wider than this band, so the script reports
    out-of-band frequency as an anomaly, not a trip.
  * Bearing temperature rises with speed. The minimum used here,
    30 + 30 * (rpm / 3000) degrees C with a 15 degree margin, is an example
    value, not taken from a real machine.

Where it runs: on a network tap on the substation PLC bus, between the SCADA
master and the PLCs. It can trigger an interlock regardless of what the
operator screen shows.

Modbus/TCP format: a 7-byte MBAP header (transaction ID, protocol ID, length,
unit ID), then a function code and data. Codes read here: 0x03, 0x04, 0x10.
Values are big-endian IEEE-754 float32.

Limits:
  * Limits should come from each machine's own historical data.
  * Register layout differs between vendors. This script assumes one layout.
  * An attacker who fakes values that agree with each other would pass.
    Backup analog sensors and rate-of-change limits help here.
"""

import struct
from dataclasses import dataclass
from typing import Any, Dict

# Modbus function codes
FC_READ_HOLDING = 0x03
FC_READ_INPUT = 0x04
FC_WRITE_MULTIPLE = 0x10
TELEMETRY_FCS = (FC_READ_HOLDING, FC_READ_INPUT, FC_WRITE_MULTIPLE)

# Limits for a 2-pole, 50 Hz generator
RATED_RPM = 3000.0        # synchronous speed at 50 Hz
OVERSPEED_TRIP_RPM = 3300.0   # ~110% rated -> mechanical trip
MAX_BEARING_C = 90.0      # thermal trip
GRID_MIN_HZ = 49.90       # IEGC 2023 operating band lower bound
GRID_MAX_HZ = 50.05       # IEGC 2023 operating band upper bound
SPIN_FLOOR_RPM = 1500.0   # above this the machine is clearly under way
TEMP_TOLERANCE_C = 15.0   # slack below the modelled temperature floor


@dataclass
class ModbusFrame:
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    function_code: int
    data: bytes


def parse_modbus_tcp(raw: bytes) -> ModbusFrame:
    """Parse a Modbus/TCP frame: 7-byte MBAP header + PDU."""
    if len(raw) < 8:
        raise ValueError("Malformed Modbus/TCP frame: shorter than MBAP+FC")
    tid, pid, length, uid, fc = struct.unpack(">HHHBB", raw[:8])
    return ModbusFrame(tid, pid, length, uid, fc, raw[8:])


def expected_temp_floor(rpm: float) -> float:
    """Conservative lower bound on steady-state bearing temp for a given speed."""
    return 30.0 + (rpm / RATED_RPM) * 30.0   # ~30 C idle -> ~60 C at rated


class ICSPhysicsSentinel:
    """Validates decoded Modbus telemetry against plant physics."""

    def evaluate(self, frame: ModbusFrame) -> Dict[str, Any]:
        if frame.function_code not in TELEMETRY_FCS:
            return {"verdict": "ALLOW",
                    "reason": f"Non-telemetry function code 0x{frame.function_code:02X}"}

        if len(frame.data) < 12:
            return {"verdict": "FLAGGED",
                    "reason": "Payload too short for speed, temperature and frequency registers"}

        rpm, temp, freq = struct.unpack(">fff", frame.data[:12])
        metrics = {"rpm": round(rpm, 1), "temp_c": round(temp, 1), "freq_hz": round(freq, 2)}

        # Check 1: overspeed.
        if rpm > OVERSPEED_TRIP_RPM:
            return {"verdict": "INTERLOCK_TRIP", "metrics": metrics,
                    "reason": f"Mechanical overspeed: {rpm:.0f} RPM > {OVERSPEED_TRIP_RPM:.0f} trip"}

        # Check 2: speed and temperature don't match. Each value can be within
        # its own limit while the pair is impossible.
        floor = expected_temp_floor(rpm)
        if rpm > SPIN_FLOOR_RPM and temp < floor - TEMP_TOLERANCE_C:
            return {"verdict": "INTERLOCK_TRIP", "metrics": metrics,
                    "reason": (f"Physics violation: {rpm:.0f} RPM reported with bearing temp "
                               f"{temp:.0f} C (impossible; floor ~{floor:.0f} C). "
                               f"Falsified SCADA telemetry.")}

        # Check 3: bearing too hot.
        if temp > MAX_BEARING_C:
            return {"verdict": "INTERLOCK_TRIP", "metrics": metrics,
                    "reason": f"Bearing over-temperature: {temp:.0f} C > {MAX_BEARING_C:.0f} C"}

        # Check 4: grid frequency outside the IEGC band.
        if not (GRID_MIN_HZ <= freq <= GRID_MAX_HZ):
            return {"verdict": "GRID_ANOMALY", "metrics": metrics,
                    "reason": f"Grid frequency {freq:.2f} Hz outside IEGC band {GRID_MIN_HZ}-{GRID_MAX_HZ} Hz"}

        return {"verdict": "NOMINAL", "metrics": metrics,
                "reason": "All physical invariants satisfied"}


def build_frame(tid: int, rpm: float, temp: float, freq: float,
                fc: int = FC_READ_HOLDING) -> bytes:
    """Assemble a Modbus/TCP frame carrying three float32 registers."""
    pdu = struct.pack(">B", fc) + struct.pack(">fff", rpm, temp, freq)
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1)  # +1 for unit id
    return mbap + pdu


def _print(label: str, v: Dict[str, Any]) -> None:
    print(f"  [{v['verdict']:<14}] {label}")
    if "metrics" in v:
        m = v["metrics"]
        print(f"      rpm={m['rpm']}  temp={m['temp_c']} C  freq={m['freq_hz']} Hz")
    print(f"      reason: {v['reason']}")


def main() -> None:
    print("=" * 70)
    print(" ics_physics_sentinel.py: SCADA false-data detector")
    print("=" * 70)
    s = ICSPhysicsSentinel()

    print("\n[NORMAL] Rated speed: 3000 RPM, bearing 68 C, 50.00 Hz")
    f1 = parse_modbus_tcp(build_frame(101, 3000.0, 68.0, 50.00))
    _print("substation PLC unit 1", s.evaluate(f1))

    print("\n[ATTACK] False readings: 3150 RPM with bearing at 22 C, 50.00 Hz")
    print("         (each value is within its limit; the pair is not possible)")
    f2 = parse_modbus_tcp(build_frame(102, 3150.0, 22.0, 50.00))
    _print("substation PLC unit 1", s.evaluate(f2))

    print("\n[ATTACK] Overspeed: 3380 RPM")
    f3 = parse_modbus_tcp(build_frame(103, 3380.0, 71.0, 50.04))
    _print("substation PLC unit 1", s.evaluate(f3))

    print("\n[INFO] Modbus frame for the false readings (hex):")
    print("      " + build_frame(102, 3150.0, 22.0, 50.00).hex())
    print("=" * 70)


if __name__ == "__main__":
    main()
