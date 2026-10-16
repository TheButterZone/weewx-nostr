# WeeWX Nostr Publisher

**Status: draft for testing and review before adding to the WeeWX wiki.**

A dependency-free WeeWX service that publishes selected weather-station observations to configured Nostr relays. It uses WeeWX loop packets, so it can run alongside the existing Weather Underground, CWOP, WOW, or other upload services. It does not read or intercept those services' outgoing requests; it publishes the selected observations directly from the WeeWX data packet.

The implementation is in `nostr_publisher.py`. Nostr event signing (secp256k1/BIP-340), Bech32 public-key encoding, and the WebSocket client are included in that file. No `pip install nostr` or `pip install websocket-client` step is required. WeeWX itself remains a requirement.

## What it publishes

- A station profile (Kind `16158`) at service startup, including the station name, geohash, power/connectivity labels, and configured sensor tags.
- A weather observation event (Kind `4223`) at the configured interval. Each event contains all configured observations that are present and numeric in the current WeeWX loop packet.
- Standard observation values are normalized to consistent units before publishing: temperature in °C, pressure in hPa, wind speed/gust in m/s, precipitation in mm, precipitation rate in mm/h, wind direction in degrees, radiation in W/m², visibility in km, and cloud base in metres. `light` is treated as lux, and `pm1`, `pm25`, and `pm10` as particulate concentrations in µg/m³.
- Additional numeric observations from custom drivers can be listed in `observations`. Unknown observations are published with their native numeric value and unit label when WeeWX provides one. Use `tag_map` to map a custom observation name to a measurement tag that your receiving frontend recognizes.
- Use `sensor_names` to label the source/device in the third position of a three-field measurement tag (for example, `temp`, value, `BMP280`). WeeWX generally cannot infer physical sensor models from observation names, so configure them where known.

The Kind `16158` and Kind `4223` weather tag conventions are application-specific, not a universal Nostr weather-data standard. This draft covers the measurement tags shown in the supplied sample (`temp`, `pressure`, `light`, `rain`, `pm1`, `pm25`, and `pm10`) plus the common WeeWX observations listed in the code. An exhaustive, authoritative list of every tag that `relaying.earth` can display has not been confirmed; unknown tags may be accepted as Nostr data without being rendered as known gauges.

## Installation

Copy `nostr_publisher.py` into the WeeWX `user` package directory:

- WeeWX 5 pip installation: usually `~/weewx-data/bin/user/`
- Legacy/package installations: use the `user` package directory for that installation, commonly `/usr/share/weewx/user/` or `/home/weewx/bin/user/`

The configured module path in the examples below is `user.nostr_publisher.Nostr`, so the file must be named `nostr_publisher.py` inside the `user` package directory.

## Configuration

Add a `[[Nostr]]` stanza under `[StdRESTful]` in `weewx.conf`:

```ini
[StdRESTful]
    [[Nostr]]
        enable = true

        # Optional station label; defaults to Station/location.
        station_name =
        station_description = WeeWX weather station

        # Geohash generated from Station/latitude and Station/longitude.
        # Precision 7 is roughly street-level; this location is public.
        geohash_precision = 7

        # Empty means a new key is generated and printed at startup.
        # Copy the printed 64-character hex key here and restart to keep
        # a stable Nostr identity.
        private_key =

        # Comma-separated wss:// or ws:// relay URLs. Empty uses the
        # built-in relay list in nostr_publisher.py.
        relays =

        # Minimum seconds between queued telemetry events.
        broadcast_interval = 300

        # WeeWX observations to publish when present in the LOOP packet.
        observations = outTemp, outHumidity, barometer, windSpeed, windDir, windGust, rain, rainRate, dayRain, dewpoint, heatindex, windchill, inTemp, inHumidity, radiation, UV, cloudbase, visibility, light, pm1, pm25, pm10

        # Optional observation-to-frontend-tag mapping for custom driver fields.
        # Example: pm2_5=pm25, particulateMatter25=pm25
        # Mapped custom values must already use the units expected by the tag.
        tag_map =

        # Optional observation-to-source/sensor labels. Without an entry,
        # the WeeWX observation name is used as the label.
        # Example: outTemp=BMP280, barometer=BMP280, light=BH1750, rain=MH-RD, pm1=PMS5003, pm25=PMS5003, pm10=PMS5003
        sensor_names =

        # Station metadata used in the Kind 16158 profile.
        power = mains
        connectivity = ethernet
```

WeeWX station latitude and longitude must be configured under `[Station]`; they are used to derive the geohash. The publisher emits the geohash, not the original latitude/longitude values, but a geohash still discloses an approximate location.

Add `user.nostr_publisher.Nostr` to the existing `process_services` list under `[Engine][[Services]]`. Keep all other services already listed, and keep the option on one line, for example:

```ini
[Engine]
    [[Services]]
        process_services = weewx.engine.StdConvert, weewx.engine.StdCalibrate, weewx.engine.StdQC, weewx.wxservices.StdWXCalculate, user.nostr_publisher.Nostr
```

Do not replace the existing `process_services` list wholesale unless you intend to remove its other services; append the publisher to the list currently in your configuration. Because the plugin binds to `NEW_LOOP_PACKET`, adding it after `StdConvert` and `StdWXCalculate` lets it see the processed packet and derived observations available at that point.

Restart WeeWX after editing `weewx.conf`.

## Notes

- The publisher is disabled unless `enable = true`.
- If `private_key` is blank, a new identity is generated. Save the printed hex private key in `weewx.conf`; otherwise, restarting WeeWX will create a different identity.
- The publishing worker performs relay network I/O outside WeeWX's main loop. It retains at most one queued telemetry snapshot so a slow relay cannot create an ever-growing backlog of stale readings.
- TLS certificate verification is enabled by default for `wss://` relays.
- Publishing requires at least one relay to accept the event; failures are logged. Availability and acceptance rules vary by relay.
- The `observations` list determines which packet fields are sent. The plugin does not automatically inspect which fields were selected by Weather Underground or CWOP, since those services may be configured differently and their outbound payloads are not a shared WeeWX interface.
- Only observations present in the loop packet are sent. Some observations may be archive-only or absent for a particular station/driver. The default list includes `light`, `pm1`, `pm25`, and `pm10`, but absent fields are simply skipped.
- `tag_map` syntax is a comma-separated list of `WeeWXObservation=frontend_tag` pairs. It can adapt alternate driver naming (for example, `pm2_5=pm25`). A custom mapped observation is sent as a three-field tag, so its value must already be in the unit expected by the target frontend.
- `sensor_names` syntax is a comma-separated list of `WeeWXObservation=SensorOrSourceName` pairs. Use actual hardware/source labels where known. Without a mapping, the observation name is used; it should not be mistaken for a detected physical sensor model.
- The cryptographic implementation is pure Python, is not constant-time, and has not undergone an independent security audit. The [BIP-340 reference material](https://bips.dev/340/) explicitly warns that a pure-Python reference implementation is not for production use. Review the risk before relying on this implementation for a high-value identity.
- For WeeWX service ordering and event binding, see the [WeeWX service-engine documentation](https://weewx.com/docs/latest/custom/service-engine/). Nostr events follow the basic [NIP-01 event format](https://github.com/nostr-protocol/nips/blob/master/01.md), while the weather tag schema described above is application-specific.

## Verification performed for this draft

- Python syntax compilation.
- BIP-340 official test vector 0: exact signature match.
- Unit-conversion checks for US Customary temperature, pressure, wind speed, and rainfall.
- Custom-observation tag/unit handling.
- Local WebSocket handshake, masked client text frame, and server response handling.

These checks do not replace testing against a real WeeWX installation and the intended Nostr relays.
