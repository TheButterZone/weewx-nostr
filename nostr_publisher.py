import base64
import hashlib
import hmac
import json
import math
import queue
import re
import threading
import logging
import os
import secrets
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit

import weewx
import weewx.units
from weewx.engine import StdService

# Nostr event signing (BIP-340 over secp256k1) and WebSocket publishing are
# implemented below using only Python's standard library.

log = logging.getLogger(__name__)

# secp256k1 domain parameters.
_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _point_add(left, right):
    """Add two secp256k1 points; None represents the point at infinity."""
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, _SECP_P - 2, _SECP_P)
    else:
        slope = (y2 - y1) * pow((x2 - x1) % _SECP_P, _SECP_P - 2, _SECP_P)
    slope %= _SECP_P
    x3 = (slope * slope - x1 - x2) % _SECP_P
    y3 = (slope * (x1 - x3) - y1) % _SECP_P
    return x3, y3


def _point_mul(scalar, point=_SECP_G):
    """Multiply a secp256k1 point by an integer using double-and-add."""
    scalar %= _SECP_N
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _tagged_hash(tag, message):
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _schnorr_sign(message, secret_scalar, aux=None):
    """Create a BIP-340 Schnorr signature. A missing aux input means zeros for test-vector reproducibility."""
    if len(message) != 32:
        raise ValueError("BIP-340 message must be exactly 32 bytes")
    if not 1 <= secret_scalar < _SECP_N:
        raise ValueError("secp256k1 private scalar is out of range")

    if aux is None:
        aux = bytes(32)
    if not isinstance(aux, bytes) or len(aux) != 32:
        raise ValueError("BIP-340 auxiliary input must be exactly 32 bytes")

    public_point = _point_mul(secret_scalar)
    px = public_point[0].to_bytes(32, "big")
    d = secret_scalar if public_point[1] % 2 == 0 else _SECP_N - secret_scalar
    masked_secret = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), _tagged_hash("BIP0340/aux", aux)))
    nonce = int.from_bytes(_tagged_hash("BIP0340/nonce", masked_secret + px + message), "big") % _SECP_N
    if nonce == 0:
        raise RuntimeError("BIP-340 generated an invalid zero nonce")
    r_point = _point_mul(nonce)
    k = nonce if r_point[1] % 2 == 0 else _SECP_N - nonce
    rx = r_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(_tagged_hash("BIP0340/challenge", rx + px + message), "big") % _SECP_N
    signature = rx + ((k + challenge * d) % _SECP_N).to_bytes(32, "big")
    if not _schnorr_verify(message, px, signature):
        raise RuntimeError("Internal BIP-340 signature verification failed")
    return signature


def _schnorr_verify(message, public_x, signature):
    """Verify a BIP-340 signature (also used as an internal signing check)."""
    if len(message) != 32 or len(public_x) != 32 or len(signature) != 64:
        return False
    px = int.from_bytes(public_x, "big")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if px >= _SECP_P or r >= _SECP_P or s >= _SECP_N:
        return False
    y_squared = (pow(px, 3, _SECP_P) + 7) % _SECP_P
    y = pow(y_squared, (_SECP_P + 1) // 4, _SECP_P)
    if (y * y) % _SECP_P != y_squared:
        return False
    if y & 1:
        y = _SECP_P - y
    public_point = (px, y)
    challenge = int.from_bytes(_tagged_hash("BIP0340/challenge", signature[:32] + public_x + message), "big") % _SECP_N
    result = _point_add(_point_mul(s), _point_mul((_SECP_N - challenge) % _SECP_N, public_point))
    return result is not None and result[1] % 2 == 0 and result[0] == r


def _convert_bits(data, from_bits, to_bits, pad=True):
    accumulator = 0
    bit_count = 0
    result = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("Invalid value for bit conversion")
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & max_value)
    if pad:
        if bit_count:
            result.append((accumulator << (to_bits - bit_count)) & max_value)
    elif bit_count >= from_bits or ((accumulator << (to_bits - bit_count)) & max_value):
        raise ValueError("Invalid incomplete bit group")
    return result


def _bech32_polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_encode(hrp, payload):
    expanded_hrp = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    values = expanded_hrp + payload
    polymod = _bech32_polymod(values + [0] * 6) ^ 1
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[value] for value in payload + checksum)


class _PublicKey:
    def __init__(self, x_coordinate):
        self._x = x_coordinate

    def hex(self):
        return self._x.hex()

    def bech32(self):
        return _bech32_encode("npub", _convert_bits(self._x, 8, 5, True))


class PrivateKey:
    """Small in-file replacement for python-nostr's PrivateKey interface."""
    def __init__(self, raw_key=None):
        if raw_key is None:
            while True:
                raw_key = secrets.token_bytes(32)
                scalar = int.from_bytes(raw_key, "big")
                if 1 <= scalar < _SECP_N:
                    break
        if not isinstance(raw_key, bytes) or len(raw_key) != 32:
            raise ValueError("Nostr private key must be exactly 32 bytes")
        scalar = int.from_bytes(raw_key, "big")
        if not 1 <= scalar < _SECP_N:
            raise ValueError("Nostr private key scalar is out of range")
        self._raw_key = raw_key
        public_point = _point_mul(scalar)
        self.public_key = _PublicKey(public_point[0].to_bytes(32, "big"))
        self._scalar = scalar

    def hex(self):
        return self._raw_key.hex()

    def sign_event(self, event):
        event.id = event.calculate_id()
        event.signature = _schnorr_sign(bytes.fromhex(event.id), self._scalar, secrets.token_bytes(32)).hex()


class Event:
    """Nostr event object with the fields used by this WeeWX service."""
    def __init__(self, public_key, kind, content="", tags=None, created_at=None):
        self.public_key = public_key
        self.kind = int(kind)
        self.content = content
        self.tags = [] if tags is None else tags
        self.created_at = int(time.time()) if created_at is None else int(created_at)
        self.id = None
        self.signature = None

    def calculate_id(self):
        serialized = json.dumps(
            [0, self.public_key, self.created_at, self.kind, self.tags, self.content],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()


class _WebSocketConnection:
    """Minimal RFC 6455 client supporting wss:// and ws:// relay connections."""
    def __init__(self, url, timeout=None):
        parsed = urlsplit(url)
        if parsed.scheme not in ("ws", "wss") or not parsed.hostname:
            raise ValueError("WebSocket URL must use ws:// or wss://")
        self._is_tls = parsed.scheme == "wss"
        self._host = parsed.hostname
        self._port = parsed.port or (443 if self._is_tls else 80)
        self._timeout = timeout
        self._buffer = b""
        self._socket = socket.create_connection((self._host, self._port), timeout=timeout)
        self._socket.settimeout(timeout)
        if self._is_tls:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._socket = context.wrap_socket(self._socket, server_hostname=self._host)

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = self._host
        if ":" in host_header and not host_header.startswith("["):
            host_header = "[" + host_header + "]"
        if self._port != (443 if self._is_tls else 80):
            host_header += ":" + str(self._port)
        client_key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {client_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: Python-stdlib-WebSocket\r\n\r\n"
        ).encode("ascii")
        self._socket.sendall(request)
        response = self._read_http_headers()
        lines = response.decode("iso-8859-1").split("\r\n")
        if not lines or " 101 " not in (lines[0] + " "):
            self.close()
            raise ConnectionError("WebSocket handshake rejected: " + (lines[0] if lines else "empty response"))
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        expected_accept = base64.b64encode(
            hashlib.sha1((client_key + _WEBSOCKET_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if not hmac.compare_digest(headers.get("sec-websocket-accept", ""), expected_accept):
            self.close()
            raise ConnectionError("Invalid WebSocket handshake accept value")
        if headers.get("upgrade", "").lower() != "websocket":
            self.close()
            raise ConnectionError("WebSocket handshake omitted Upgrade: websocket")

    def _read_http_headers(self):
        while b"\r\n\r\n" not in self._buffer:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed during WebSocket handshake")
            self._buffer += chunk
            if len(self._buffer) > 65536:
                raise ConnectionError("WebSocket handshake headers are too large")
        response, self._buffer = self._buffer.split(b"\r\n\r\n", 1)
        return response

    def _read_exactly(self, length):
        while len(self._buffer) < length:
            chunk = self._socket.recv(max(4096, length - len(self._buffer)))
            if not chunk:
                raise ConnectionError("WebSocket connection closed")
            self._buffer += chunk
        data, self._buffer = self._buffer[:length], self._buffer[length:]
        return data

    def _send_frame(self, opcode, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        length = len(payload)
        first = bytes((0x80 | (opcode & 0x0F),))
        mask_key = os.urandom(4)
        if length < 126:
            header = first + bytes((0x80 | length,))
        elif length <= 0xFFFF:
            header = first + bytes((0x80 | 126,)) + struct.pack("!H", length)
        else:
            header = first + bytes((0x80 | 127,)) + struct.pack("!Q", length)
        masked = bytes(value ^ mask_key[index & 3] for index, value in enumerate(payload))
        self._socket.sendall(header + mask_key + masked)

    def send(self, payload):
        self._send_frame(0x1, payload)

    def _read_frame(self):
        first, second = self._read_exactly(2)
        final = bool(first & 0x80)
        if first & 0x70:
            raise ConnectionError("Unsupported WebSocket RSV bits")
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exactly(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exactly(8))[0]
        if length > 1048576:
            raise ConnectionError("WebSocket frame exceeds the 1 MiB limit")
        if opcode >= 0x8 and (not final or length > 125):
            raise ConnectionError("Invalid WebSocket control frame")
        mask_key = self._read_exactly(4) if masked else b""
        payload = self._read_exactly(length)
        if masked:
            payload = bytes(value ^ mask_key[index & 3] for index, value in enumerate(payload))
        return final, opcode, payload

    def recv(self):
        fragments = []
        message_opcode = None
        while True:
            final, opcode, payload = self._read_frame()
            if opcode == 0x8:
                raise ConnectionError("WebSocket peer closed the connection")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x1, 0x2):
                if message_opcode is not None:
                    raise ConnectionError("Unexpected new WebSocket data frame")
                message_opcode = opcode
                fragments = [payload]
            elif opcode == 0x0:
                if message_opcode is None:
                    raise ConnectionError("Unexpected WebSocket continuation frame")
                fragments.append(payload)
            else:
                raise ConnectionError("Unsupported WebSocket opcode")
            if final:
                data = b"".join(fragments)
                return data.decode("utf-8") if message_opcode == 0x1 else data

    def close(self):
        sock = getattr(self, "_socket", None)
        if sock is None:
            return
        try:
            if sock.fileno() >= 0:
                try:
                    self._send_frame(0x8, b"")
                except (OSError, ConnectionError):
                    pass
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        except OSError:
            pass


def create_connection(url, timeout=None):
    """Open a verified TLS WebSocket connection using the standard library."""
    return _WebSocketConnection(url, timeout=timeout)

def geohash_encode(latitude, longitude, precision=7):
    """Pure-Python geohash encoder."""
    if not 1 <= int(precision) <= 12:
        raise ValueError("geohash precision must be between 1 and 12")
    base32 = "0123456789bcdefghjkmnpqrstuvwxyz"
    lat_interval, lon_interval = (-90.0, 90.0), (-180.0, 180.0)
    geohash = []
    bits = [16, 8, 4, 2, 1]
    bit = 0
    ch = 0
    even = True

    while len(geohash) < precision:
        if even:
            mid = (lon_interval[0] + lon_interval[1]) / 2.0
            if longitude > mid:
                ch |= bits[bit]
                lon_interval = (mid, lon_interval[1])
            else:
                lon_interval = (lon_interval[0], mid)
        else:
            mid = (lat_interval[0] + lat_interval[1]) / 2.0
            if latitude > mid:
                ch |= bits[bit]
                lat_interval = (mid, lat_interval[1])
            else:
                lat_interval = (lat_interval[0], mid)
        even = not even
        if bit < 4:
            bit += 1
        else:
            geohash.append(base32[ch])
            bit = 0
            ch = 0
    return "".join(geohash)


# Observation names and tag/unit conventions used for common weather data.
# The unit conversions here make standard observations independent of the
# WeeWX database unit system: temperatures are °C, pressure is hPa, wind speed
# is m/s, and precipitation is mm (or mm/hour for rates).
_OBSERVATION_SPECS = {
    "outTemp": ("temp", "temperature", 1),
    "inTemp": ("temp", "temperature", 1),
    "dewpoint": ("temp", "temperature", 1),
    "heatindex": ("temp", "temperature", 1),
    "windchill": ("temp", "temperature", 1),
    "appTemp": ("temp", "temperature", 1),
    "humidex": ("temp", "temperature", 1),
    "outHumidity": ("humidity", "humidity", 1),
    "inHumidity": ("humidity", "humidity", 1),
    "barometer": ("pressure", "pressure", 1),
    "pressure": ("pressure", "pressure", 1),
    "light": ("light", "illuminance", 1),
    "pm1": ("pm1", "concentration", 0),
    "pm25": ("pm25", "concentration", 0),
    "pm10": ("pm10", "concentration", 0),
    "windSpeed": ("wind_speed", "speed", 2),
    "windGust": ("wind_gust", "speed", 2),
    "windDir": ("wind_direction", "direction", 1),
    "windGustDir": ("wind_gust_direction", "direction", 1),
    "windrun": ("windrun", "distance", 2),
    "rain": ("rain", "rain", 2),
    "rainRate": ("rain_rate", "rain_rate", 2),
    "hourRain": ("rain", "rain", 2),
    "dayRain": ("rain", "rain", 2),
    "weekRain": ("rain", "rain", 2),
    "monthRain": ("rain", "rain", 2),
    "yearRain": ("rain", "rain", 2),
    "rain24": ("rain", "rain", 2),
    "radiation": ("solar_radiation", "radiation", 1),
    "UV": ("uv_index", "index", 1),
    "cloudbase": ("cloudbase", "height", 1),
    "visibility": ("visibility", "visibility", 2),
    "ET": ("evapotranspiration", "rain", 2),
    "dayET": ("evapotranspiration", "rain", 2),
    "monthET": ("evapotranspiration", "rain", 2),
    "yearET": ("evapotranspiration", "rain", 2),
}

_DEFAULT_OBSERVATIONS = (
    "outTemp,outHumidity,barometer,pressure,windSpeed,windDir,windGust,"
    "rain,rainRate,dayRain,dewpoint,heatindex,windchill,inTemp,inHumidity,"
    "radiation,UV,cloudbase,visibility,light,pm1,pm25,pm10"
)

_DEFAULT_RELAYS = (
    "wss://relay.relaying.earth",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
    "wss://bitcoiner.social",
    "wss://relay.wellorder.net",
    "wss://relay.nostrfy.org",
    "wss://relay.ditto.pub",
    "wss://relay.dreamith.to",
)


def _csv_values(value):
    """Parse a WeeWX config option containing comma-separated values."""
    if isinstance(value, (list, tuple)):
        parts = value
    else:
        parts = str(value or "").split(",")
    return [str(part).strip() for part in parts if str(part).strip()]


def _weewx_unit_name(observation, unit_system):
    """Return WeeWX's native unit label for an unrecognized observation."""
    try:
        unit_type = weewx.units.getStandardUnitType(observation, unit_system)
        if unit_type:
            return str(unit_type[0])
    except (AttributeError, KeyError, TypeError, ValueError):
        pass
    return "native"


def _csv_mapping(value):
    """Parse comma-separated observation=value mappings from weewx.conf."""
    if isinstance(value, (list, tuple)):
        parts = value
    else:
        parts = str(value or "").split(",")
    result = {}
    for part in parts:
        part = str(part).strip()
        if not part:
            continue
        separator = "=" if "=" in part else (":" if ":" in part else None)
        if separator is None:
            log.warning("Nostr: Ignoring mapping without '=': %s", part)
            continue
        source, target = part.split(separator, 1)
        source, target = source.strip(), target.strip()
        if source and target:
            result[source] = target
    return result


class Nostr(StdService):
    """Publish a WeeWX weather station's observations to Nostr relays."""

    def __init__(self, engine, config_dict):
        super().__init__(engine, config_dict)

        site_dict = config_dict.get("StdRESTful", {}).get("Nostr", {})
        if str(site_dict.get("enable", "false")).strip().lower() not in ("true", "1", "yes", "on"):
            log.info("Nostr: Publisher disabled in configuration.")
            return

        try:
            self.broadcast_interval = int(site_dict.get("broadcast_interval", 300))
            self.geohash_precision = int(site_dict.get("geohash_precision", 7))
            if self.broadcast_interval < 1:
                raise ValueError("broadcast_interval must be at least 1 second")
            if not 1 <= self.geohash_precision <= 12:
                raise ValueError("geohash_precision must be between 1 and 12")
        except (TypeError, ValueError) as e:
            log.error("Nostr: Invalid configuration: %s", e)
            return

        self.observations = list(dict.fromkeys(
            _csv_values(site_dict.get("observations", _DEFAULT_OBSERVATIONS))
        ))
        if not self.observations:
            self.observations = _csv_values(_DEFAULT_OBSERVATIONS)
        # Optional mappings adapt site-specific WeeWX observation names to the
        # measurement keys and source labels expected by a receiving frontend.
        self.tag_map = _csv_mapping(site_dict.get("tag_map", ""))
        self.sensor_names = _csv_mapping(site_dict.get("sensor_names", ""))

        config_relays = site_dict.get("relays", "")
        self.relays = _csv_values(config_relays) or list(_DEFAULT_RELAYS)
        self.station_description = str(
            site_dict.get("station_description", "WeeWX weather station")
        ).strip() or "WeeWX weather station"
        self.power = str(site_dict.get("power", "mains")).strip() or "mains"
        self.connectivity = str(site_dict.get("connectivity", "ethernet")).strip() or "ethernet"

        station_dict = config_dict.get("Station", {})
        self.station_name = str(
            site_dict.get("station_name", "") or station_dict.get("location", "WeeWX Weather Station")
        ).strip() or "WeeWX Weather Station"
        try:
            latitude = float(station_dict["latitude"])
            longitude = float(station_dict["longitude"])
            if not math.isfinite(latitude) or not -90 <= latitude <= 90:
                raise ValueError("latitude must be between -90 and 90")
            if not math.isfinite(longitude) or not -180 <= longitude <= 180:
                raise ValueError("longitude must be between -180 and 180")
            self.geohash = geohash_encode(latitude, longitude, self.geohash_precision)
        except (KeyError, TypeError, ValueError) as e:
            log.error("Nostr: Missing or invalid Station latitude/longitude: %s", e)
            return

        sk_hex = str(site_dict.get("private_key", "") or "").strip()
        try:
            if sk_hex:
                self.pk = PrivateKey(bytes.fromhex(sk_hex))
            else:
                self.pk = PrivateKey()
                print(
                    "\n[NOSTR SETUP] Generated npub: %s\n"
                    "[NOSTR SETUP] Save this private key in weewx.conf under [[Nostr]] "
                    "as private_key = '%s'. The generated key will change on restart "
                    "unless you save it.\n" % (self.pk.public_key.bech32(), self.pk.hex()),
                    flush=True,
                )
                log.warning("Nostr: Generated a new key; save it in weewx.conf to keep the same identity.")
        except (TypeError, ValueError) as e:
            log.error("Nostr: Invalid private_key; expected 64 hexadecimal characters: %s", e)
            return

        self.last_broadcast_time = 0.0
        self._stopping = threading.Event()
        # A single pending item is enough: if publishing falls behind, keep the
        # most recent sensor snapshot instead of building up a stale queue.
        self._publish_queue = queue.Queue(maxsize=1)
        self.bind(weewx.NEW_LOOP_PACKET, self.new_loop_packet)
        self._worker = threading.Thread(
            target=self._publisher_worker,
            name="WeeWX-Nostr-Publisher",
            daemon=True,
        )
        self._worker.start()
        log.info(
            "Nostr: Initialized for station '%s' (geohash %s); observations=%s; interval=%ss.",
            self.station_name, self.geohash, ",".join(self.observations), self.broadcast_interval,
        )

    def _sensor_tag(self, observation):
        """Return the Nostr measurement tag used for an observation."""
        configured_tag = getattr(self, "tag_map", {}).get(observation)
        if configured_tag:
            return configured_tag
        spec = _OBSERVATION_SPECS.get(observation)
        if spec:
            return spec[0]
        if re.fullmatch(r"(?:soilTemp|extraTemp)\d+", observation):
            return "temp"
        # Preserve support for custom drivers and gauges. Unknown observations
        # are published with their native WeeWX unit, which is appended to the tag.
        snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", observation).lower()
        return snake_name or "observation"

    def _normalise_value(self, observation, value, unit_system):
        """Return (numeric value, tag, decimal places, unit) for one observation."""
        spec = _OBSERVATION_SPECS.get(observation)
        if spec is None:
            # Common custom temperature observations can still be normalized.
            if re.fullmatch(r"(?:soilTemp|extraTemp)\d+", observation):
                spec = ("temp", "temperature", 1)
            else:
                try:
                    numeric = float(value)
                except (TypeError, ValueError, OverflowError):
                    return None
                if not math.isfinite(numeric):
                    return None
                return numeric, self._sensor_tag(observation), 3, _weewx_unit_name(observation, unit_system)

        tag, quantity, decimals = spec
        numeric = float(value)
        is_us = unit_system == getattr(weewx, "US", 1)
        is_metric = unit_system == getattr(weewx, "METRIC", 16)

        if quantity == "temperature":
            if is_us:
                numeric = (numeric - 32.0) * 5.0 / 9.0
            unit = "C"
        elif quantity == "pressure":
            if is_us:
                numeric *= 33.8638866667  # inHg -> hPa
            unit = "hPa"
        elif quantity == "speed":
            if is_us:
                numeric *= 0.44704  # mph -> m/s
            elif is_metric:
                numeric /= 3.6  # km/h -> m/s
            unit = "m/s"
        elif quantity in ("rain", "rain_rate"):
            if is_us:
                numeric *= 25.4  # inch -> mm
            elif is_metric:
                numeric *= 10.0  # cm -> mm
            unit = "mm/h" if quantity == "rain_rate" else "mm"
        elif quantity == "direction":
            unit = "degree"
        elif quantity == "humidity":
            unit = "%"
        elif quantity == "radiation":
            unit = "W/m2"
        elif quantity == "index":
            unit = "index"
        elif quantity == "height":
            if is_us:
                numeric *= 0.3048  # feet -> metres
            unit = "m"
        elif quantity == "visibility":
            if is_us:
                numeric *= 1.609344  # miles -> km
            unit = "km"
        elif quantity == "distance":
            if is_us:
                numeric *= 1.609344  # miles -> km
            unit = "km"
        elif quantity == "illuminance":
            # WeeWX custom observations mapped to `light` should be in lux.
            unit = "lux"
        elif quantity == "concentration":
            # Conventional particulate sensor unit; custom values are assumed
            # to already be expressed in micrograms per cubic metre.
            unit = "ug/m3"
        else:
            unit = _weewx_unit_name(observation, unit_system)

        if not math.isfinite(numeric):
            return None
        return numeric, tag, decimals, unit

    @staticmethod
    def _format_value(value, decimals):
        return format(value, ".%df" % decimals)

    def _snapshot(self, packet):
        unit_system = packet.get("usUnits", getattr(weewx, "US", 1))
        readings = []
        for observation in self.observations:
            value = packet.get(observation)
            if value is None:
                continue
            try:
                normalized = self._normalise_value(observation, value, unit_system)
            except (TypeError, ValueError, OverflowError):
                log.debug("Nostr: Skipping non-numeric observation %s=%r", observation, value)
                continue
            if normalized is None:
                continue
            numeric, tag, decimals, unit = normalized
            # Existing weather-map tags use [type, value, sensor]. Appending a
            # unit to custom tags keeps arbitrary driver observations interpretable.
            sensor_name = self.sensor_names.get(observation, observation)
            tag_value = [tag, self._format_value(numeric, decimals), sensor_name]
            if (
                observation not in _OBSERVATION_SPECS
                and observation not in self.tag_map
                and not re.fullmatch(r"(?:soilTemp|extraTemp)\d+", observation)
            ):
                # Custom, unmapped tags carry an extra native-unit field. Known
                # frontend tags use the three-field [type, value, sensor] form.
                tag_value.append(unit)
            readings.append(tag_value)
        return readings

    def new_loop_packet(self, event):
        """Queue a snapshot after WeeWX has processed the LOOP packet."""
        now = time.monotonic()
        if now - self.last_broadcast_time < self.broadcast_interval:
            return
        packet = event.packet
        readings = self._snapshot(packet)
        if not readings:
            return

        timestamp = packet.get("dateTime")
        try:
            timestamp = int(timestamp) if timestamp is not None else int(time.time())
        except (TypeError, ValueError, OverflowError):
            timestamp = int(time.time())
        item = (readings, timestamp)
        try:
            self._publish_queue.put_nowait(item)
        except queue.Full:
            # Replace a stale waiting snapshot with the newest available data.
            try:
                self._publish_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._publish_queue.put_nowait(item)
            except queue.Full:
                log.debug("Nostr: Publisher queue is full; skipped this snapshot.")
                return
        self.last_broadcast_time = now

    def _publisher_worker(self):
        """Perform network I/O off WeeWX's main event loop."""
        self.broadcast_station_profile()
        while not self._stopping.is_set():
            try:
                item = self._publish_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            readings, timestamp = item
            self.broadcast_event(readings, timestamp)

    def shutDown(self):
        self._stopping.set()
        try:
            self._publish_queue.put_nowait(None)
        except queue.Full:
            try:
                self._publish_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._publish_queue.put_nowait(None)
            except queue.Full:
                pass
        worker = getattr(self, "_worker", None)
        if worker is not None and worker.is_alive():
            worker.join(timeout=2.0)

    @staticmethod
    def _event_dict(event):
        return {
            "id": event.id,
            "pubkey": event.public_key,
            "created_at": event.created_at,
            "kind": event.kind,
            "tags": event.tags,
            "content": event.content,
            "sig": event.signature,
        }

    def _publish_event(self, event, description):
        self.pk.sign_event(event)
        payload = json.dumps(
            ["EVENT", self._event_dict(event)],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        success = 0
        for relay_url in self.relays:
            ws = None
            try:
                # TLS certificate verification is enabled by default.
                ws = create_connection(relay_url, timeout=4)
                ws.send(payload)
                response = ws.recv()
                response_data = json.loads(response)
                if (
                    isinstance(response_data, list)
                    and len(response_data) >= 3
                    and response_data[0] == "OK"
                    and response_data[1] == event.id
                    and response_data[2] is True
                ):
                    success += 1
                else:
                    log.debug("Nostr: Relay %s did not accept %s: %r", relay_url, description, response_data)
            except Exception as e:
                log.debug("Nostr: Relay %s failed for %s: %s", relay_url, description, e)
            finally:
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
        return success

    def broadcast_station_profile(self):
        """Publish a Kind 16158 profile describing the station's configured sensors."""
        tags = [
            ["name", self.station_name],
            ["description", self.station_description],
            ["g", self.geohash],
            ["power", self.power],
            ["connectivity", self.connectivity],
        ]
        seen_sensors = set()
        for observation in self.observations:
            sensor_type = self._sensor_tag(observation)
            sensor_name = self.sensor_names.get(observation, observation)
            sensor = (sensor_type, sensor_name)
            if sensor in seen_sensors:
                continue
            seen_sensors.add(sensor)
            tags.append(["sensor", sensor_type, sensor_name])
            tags.append(["sensor_status", sensor_type, sensor_name, "ok"])

        event = Event(
            public_key=self.pk.public_key.hex(),
            kind=16158,
            content="",
            tags=tags,
        )
        success = self._publish_event(event, "station profile")
        if success:
            log.info("Nostr: Published station profile (Kind 16158) to %d relay(s).", success)

    def broadcast_event(self, readings, created_at=None):
        """Publish one Kind 4223 event containing all selected available readings."""
        pubkey_hex = self.pk.public_key.hex()
        tags = [
            ["d", "weather-" + self.geohash],
            ["a", "16158:%s:" % pubkey_hex],
            ["t", "weather"],
            ["t", "weewx"],
        ]
        tags.extend(readings)
        event = Event(
            public_key=pubkey_hex,
            kind=4223,
            content="",
            tags=tags,
            created_at=created_at,
        )
        success = self._publish_event(event, "weather observation")
        if success:
            log.info("Nostr: Published %d weather observation(s) to %d relay(s).", len(readings), success)
        else:
            log.warning("Nostr: No relay confirmed the weather observation event.")
        return success > 0
