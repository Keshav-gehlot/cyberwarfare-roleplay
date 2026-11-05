# Viva and Presentation Prep

## Slide outline

**1. Title**
- Cyber Warfare 2035: three emerging threats and a detector for each.
- Scenario: a coordinated attack on Indian national infrastructure.
- Argument: these attacks avoid signature-based tools, so detection has to check protocol structure and physical behaviour.

**2. Threats**
- Post-quantum downgrade: removing ML-KEM from TLS so traffic can be decrypted later.
- OT sabotage: firmware that reports false sensor values to SCADA.
- Satellite spoofing: generated radar data injected at a ground station.

**3. Detectors**
- `pq_downgrade_guard` checks the TLS key-exchange group and key share size.
- `ics_physics_sentinel` checks Modbus readings against what the machine can physically do.
- `sar_jitter_analyzer` checks whether a feed's phase noise looks natural.

**4. Demo**
- Run each Python file: one normal case, one or more attack cases.
- Open each dashboard and click through the scenarios.

**5. Limits and next steps**
- Inputs are simulated and thresholds are fixed.
- A real deployment needs thresholds tuned to the site, backup sensors, and checks that combine several signals.
- Relevant standards: IEC 62443 for industrial control; FIPS 203, 204 and 205 for post-quantum cryptography.

## Likely questions

**1. Can a quantum computer break ML-KEM-768?**
No known quantum algorithm breaks it efficiently. ML-KEM (FIPS 203) is a lattice-based scheme built to resist quantum attacks. My tool detects an attacker removing ML-KEM from the handshake so the session uses X25519 alone, which a large quantum computer could break with Shor's algorithm.

**2. What is "harvest now, decrypt later"?**
An attacker records encrypted traffic today and stores it until a quantum computer can decrypt it. Downgrade attacks are therefore worth stopping now, before such computers exist.

**3. Why check the key share length as well as the group?**
An attacker who controls a TLS-terminating proxy could keep the hybrid group ID (0x11EC) but cut the ML-KEM bytes. The client share for X25519MLKEM768 is 1216 bytes: 1184 for the ML-KEM-768 encapsulation key and 32 for X25519. A shorter share means the ML-KEM part is missing.

**3a. Doesn't TLS 1.3 already stop someone changing the handshake?**
Yes, against a plain eavesdropper. TLS 1.3 signs the whole handshake transcript, so edits in transit make the handshake fail. The attack in my scenario needs a box that terminates TLS, such as a compromised inspection proxy, or an endpoint misconfigured to accept classical-only groups. That's why the guard runs at the gateway and checks what was actually negotiated.

**4. Why use physics instead of malware signatures?**
Signatures only match malware that has been seen before. New or self-modifying malware has no signature. A turbine near rated speed will always run hot, whoever wrote the malware. If the reported values break that rule, the data is false. Stuxnet worked by replaying normal readings, which is the case this check covers.

**5. Describe the Modbus frame your tool reads.**
A 7-byte MBAP header (transaction ID, protocol ID, length, unit ID), then the PDU: a 1-byte function code and the data. The tool reads function codes 0x03, 0x04 and 0x10, then decodes three big-endian IEEE-754 float32 values: speed, bearing temperature and grid frequency.

**6. Why 3000 RPM and 50 Hz?**
India's grid runs at 50 Hz. Synchronous speed is 120 × f / p, so a 2-pole generator turns at 3000 RPM. 3600 RPM is the 60 Hz value used in North America. The frequency check uses the IEGC 2023 band of 49.90 to 50.05 Hz. Relay trip settings are wider than this band, so the tool reports an anomaly rather than a trip.

**7. How does the SAR detector separate real data from fake?**
A real downlink has random phase noise from heat, the atmosphere and the oscillator. The tool takes the last 50 samples and calculates the standard deviation of the phase changes (σ) and their Shannon entropy. Generated data varies too little, so one or both values fall below the threshold.

**8. What does Shannon entropy measure here?**
H = −Σ p log₂ p, in bits. Real noise spreads across many values, giving high entropy. Generated data clusters on a few values, giving low entropy. It can catch regular patterns that σ alone would miss.

**9. How would you reduce false positives?**
Tune thresholds to conditions such as weather, link quality and load. Require more than one signal before raising an alert. Add limits on rate of change. Confirm against a second, independent sensor. The fixed thresholds are the first thing I would replace.

**10. Why three separate tools instead of one system?**
Each works at a different point in the network: the TLS gateway, the PLC bus and the satellite ground decoder. Keeping them separate means each can be tested and deployed on its own. In production they would all send alerts to the same SIEM.

**11. How could an attacker beat the SAR detector?**
By adding noise with the same statistics as a real downlink. The dashboard's "Deepfake with injected noise" mode shows this: the fake feed passes. Defending against it means checking the feed against a separate source, such as passive RF or orbital data.

## 60-second summary

"By 2035, attacks will be fast and will hit several systems at once. I built a scenario around a coordinated attack on Indian infrastructure, and three separate detectors for it. The first watches TLS handshakes and blocks sessions where the post-quantum key exchange has been removed, so recorded traffic can't be decrypted later. The second reads Modbus traffic from a substation and checks it against the machine's physics, which catches false sensor data even from unknown malware. The third flags satellite feeds whose noise is too regular to be real. Each runs on its own with a dashboard. All three work by checking protocol structure or physical behaviour instead of matching signatures. The main limits are simulated inputs and fixed thresholds; a real system would need tuned models, backup sensors and cross-checks."
