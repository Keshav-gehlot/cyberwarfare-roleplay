# Operation Chimera Dawn: Incident Commander Briefing

This is a fictional role-play set in 2035. The technology is speculative, but each attack is based on a real threat or standard from 2026.

You are the Lead Incident Commander, Cyber Defense and Resilience Unit, National Cyber Defense Command (NCDC), India.

**Time:** 14 October 2035, 03:42 IST
**Place:** Joint Operations Centre, Strategic Cyber Command

## Situation

At 03:36 a state-backed group, designated NEXUS-35, began a coordinated attack on three national systems. Automated response playbooks did not complete; their containment nodes were cut off before they ran. Commander Rao, the SOC lead, has asked for a direction from you.

## The three attacks

**Alpha: TLS downgrade on the C2 backbone.** An attacker in the network path is removing the post-quantum part of our hybrid TLS 1.3 handshakes. Sessions fall back to classical X25519 only. The likely aim is to record traffic now and decrypt it once quantum computers can break X25519. ML-KEM itself has not been broken; the attacker is removing it from the handshake.

**Beta: Falsified SCADA data at a 400 kV substation.** Tampered firmware, delivered through a supply-chain update, is sending false sensor values to the control room. Operators see normal bearing temperatures while the turbine is pushed above rated speed.

**Gamma: Fake satellite radar data.** A ground station has been compromised and is feeding generated SAR imagery into the reconnaissance system. It shows a carrier group moving off the west coast. The feed's phase noise is lower than a real downlink would have.

## Decision point

The Deputy NSA is on the line. Northern grid frequency is above 50.5 Hz. If it is not brought back within eight minutes, protection relays will start tripping and the northern industrial region will lose power. General Operations is preparing to scramble air defence based on the radar picture.

## Options

1. **Contain the C2 links.** Cut the fallback path, rotate keys, and require post-quantum key exchange on all command links. This adds latency but stops forged commands.
2. **Clean the substation.** Put a defensive agent on the PLC bus to patch firmware and force hardware interlocks. This may trip or disable working PLCs.
3. **Check the radar feed.** Compare the SAR data against an independent passive RF source, tell General Operations to hold, and run forensics on the ground station.
4. **Your own plan.** Set out your own order of actions: protocols, forensics, network segmentation, or points to break the attack chain.

What is your first order, and why?

The three apps in this folder are the detection tools behind options 1 to 3.
