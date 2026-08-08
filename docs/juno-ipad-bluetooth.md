# Juno iPad Bluetooth surface

## Purpose

Grabowski exposes three typed Bluetooth Low Energy operations through the locally paired Juno iPad agent:

- `ipad_bluetooth_scan` performs one bounded CoreBluetooth advertisement scan without a service filter.
- `ipad_bluetooth_inspect` rescans for one exact CoreBluetooth peripheral identifier, connects temporarily when the advertisement is connectable, enumerates GATT services and characteristic metadata, then cancels the connection.
- `ipad_bluetooth_read` rescans for one exact peripheral, connects temporarily, discovers one exact service and at most eight exact requested readable characteristics, performs one-shot value reads, returns bounded raw payloads with SHA-256 evidence, then cancels the connection.

The typed surface exists so callers do not need arbitrary Python for ordinary BLE observation or exact bounded reads.

## Authority boundary

All three operations are device jobs and retain Juno's exact agent-instance binding, explicit session escalation, digest-bound code execution, transport verification, bounded runtime and receipt trail.

The fixed Bluetooth job source can initialize `CBCentralManager`, scan, temporarily connect, discover services and characteristics, and disconnect. Only `ipad_bluetooth_read` may additionally call `readValueForCharacteristic` for the exact requested characteristics after CoreBluetooth reports them readable. It returns raw Base64 bytes, byte length and SHA-256; it does not interpret proprietary payloads as commands or state.

The fixed source does **not** call characteristic writes or notification subscriptions. It does not call pairing APIs or authentication-bypass APIs. Host semantic validation requires `writes_attempted=false` and `pairing_requested_by_tool=false`; read results additionally require `subscriptions_attempted=false`, exact target identity, valid Base64, size bounds and payload SHA-256. Read discovery is restricted to the requested service so unrelated GATT services cannot delay the target read. Connection/discovery/read timeouts remain explicit indeterminate statuses and are never collapsed into a false `not_found` claim.

`ipad_bluetooth_inspect` remains metadata-only. A characteristic being reported as writable does not grant control authority. `ipad_bluetooth_read` grants only the exact one-shot private-content read requested by its arguments and no broader device-control authority.

## Bounds

- Scan duration: 1–12 seconds.
- Inspect/read rescan duration: 1–8 seconds.
- GATT discovery/read window: 1–8 seconds.
- Scan result: at most 128 devices.
- GATT metadata result: at most 64 services and 128 characteristics per service.
- Read request: one exact service and 1–8 unique 16-, 32- or 128-bit characteristic UUIDs.
- Read payload: at most 4 KiB per characteristic and 16 KiB total.
- Advertisement descriptions are bounded to 4 KiB each.
- Whole device result remains bounded to the Juno 256 KiB result ceiling.
- Device target must be one canonical CoreBluetooth UUID returned by the iPad; it is not a Bluetooth MAC address.

A unique Objective-C delegate class name is generated for every job so the persistent Juno process does not collide with a class registered by an earlier scan.

## Foreground behavior

The current Juno app declares Bluetooth usage consent but does not declare the `bluetooth-central` background mode. iPadOS can therefore suppress general discovery while Juno is in the background. Results expose application state; this contract does not claim background BLE entitlement.

## Privacy and interpretation

Discovery does not establish ownership of a nearby device. RSSI is not a reliable distance measurement. CoreBluetooth peripheral UUIDs are local iPadOS identifiers. Characteristic values can be private device content; the read surface therefore requires explicit exact targets and returns raw bytes without claiming protocol meaning. A read failure caused by encryption, authentication or pairing requirements is reported as an error and is not bypassed.

## Evidence

Host tests in `tests/test_juno_bluetooth_tools.py` enforce input/result bounds, exact-target validation, digest binding, no-write/no-subscribe/no-pairing markers, payload size/hash validation and the absence of write/subscribe calls from the fixed job source.

The live feasibility proof on 8 August 2026 established foreground scanning and temporary GATT metadata access through the paired iPad. Runtime read evidence is recorded separately by exact tool receipts rather than treated as a source-code claim.
