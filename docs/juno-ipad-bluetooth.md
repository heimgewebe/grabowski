# Juno iPad Bluetooth surface

## Purpose

Grabowski exposes two typed Bluetooth Low Energy operations through the locally paired Juno iPad agent:

- `ipad_bluetooth_scan` performs one bounded CoreBluetooth advertisement scan without a service filter.
- `ipad_bluetooth_inspect` rescans for one exact CoreBluetooth peripheral identifier, connects temporarily when the advertisement is connectable, enumerates GATT services and characteristic metadata, then cancels the connection.

The typed surface exists so callers do not need to submit arbitrary Python merely to observe nearby BLE metadata.

## Authority boundary

Both operations are device jobs and therefore retain Juno's exact agent-instance binding, explicit session escalation, digest-bound code execution, transport verification, bounded runtime and receipt trail.

The fixed Bluetooth job source can:

- initialize `CBCentralManager`,
- scan for BLE advertisements,
- observe names, RSSI, connectability, advertised service UUIDs and bounded advertisement descriptions,
- connect to the exact requested CoreBluetooth peripheral identifier for inspection,
- call `discoverServices`,
- call `discoverCharacteristics`,
- return characteristic property bits,
- cancel the temporary connection.

The fixed source does **not** call characteristic value reads, characteristic writes, notification subscriptions, pairing APIs or authentication-bypass APIs. Host semantic validation additionally requires `writes_attempted=false` and `pairing_requested_by_tool=false` in every successful device result.

`ipad_bluetooth_inspect` is metadata inspection, not device control. A characteristic being reported as writable means only that CoreBluetooth advertised that property; the tool does not exercise it.

## Bounds

- Scan duration: 1–12 seconds.
- Inspect rescan duration: 1–8 seconds.
- GATT discovery window: 1–8 seconds.
- Scan result: at most 128 devices.
- GATT result: at most 64 services and 128 characteristics per service.
- Advertisement descriptions are bounded to 4 KiB each.
- Whole device result is bounded to the Juno 256 KiB result ceiling.
- Inspect target must be one canonical CoreBluetooth UUID returned by the iPad; it is not a Bluetooth MAC address.

A unique Objective-C delegate class name is generated for every job so the persistent Juno process does not collide with a class registered by an earlier scan.

## Foreground behavior

The current Juno app declares Bluetooth usage consent but does not declare the `bluetooth-central` background mode. iPadOS can therefore suppress general discovery while Juno is in the background. Results expose the application state so callers can distinguish a technically successful scan from a foreground-capable one.

This contract does not claim background BLE entitlement. Adding and validating that entitlement is a separate app/deployment change.

## Privacy and interpretation

Discovery does not establish ownership of a nearby device. RSSI is a radio-strength observation and is not a reliable distance measurement. CoreBluetooth peripheral UUIDs are local identifiers assigned by iPadOS and must not be presented as hardware MAC addresses.

## Evidence

Host tests in `tests/test_juno_bluetooth_tools.py` enforce input/result bounds, exact-target validation, digest binding, no-write/no-pairing result markers and the absence of value-read/write/subscribe calls from the fixed job source.

The initial live feasibility proof on 8 August 2026 used the paired iPad 10th generation running iPadOS 26.6. With Juno in the foreground, CoreBluetooth discovered multiple nearby BLE advertisers and successfully enumerated GATT metadata on several connectable peripherals. Those exploratory calls are not part of this source contract; the typed tools replace that ad-hoc path.
