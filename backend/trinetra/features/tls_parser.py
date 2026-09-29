"""
TLS and QUIC Metadata Parser for Trinetra.
Specifically engineered for T-d (Malware in Encrypted Sessions):
1. Pure Python JA3 extraction from TLS ClientHello (RFC compliant)
2. Pure Python JA3S extraction from TLS ServerHello
3. Packet Size and Timing (PST) sequence feature extraction to defend against
   Chrome extension-order randomization and TLS fingerprint evasion.
"""
import hashlib
import struct
from typing import List, Optional, Tuple, Dict, Any

# GREASE (Generate Random Extensions And Sustain Extensibility) values to ignore as per RFC 8701
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses a TLS ClientHello from raw payload bytes.
    Extracts SSL version, Cipher Suites, Extensions, Elliptic Curves, and EC Point Formats.
    Constructs JA3 string and MD5 hash.
    """
    try:
        # Check TLS Record Header: Type 22 (Handshake), Version >= 0x0300
        if len(payload) < 5:
            return None
        content_type, record_ver, record_len = struct.unpack("!BHH", payload[:5])
        if content_type != 22:
            return None

        # Check Handshake Header: Type 1 (ClientHello)
        if len(payload) < 9:
            return None
        handshake_type = payload[5]
        if handshake_type != 1:
            return None

        offset = 9
        if offset + 34 > len(payload):
            return None

        # Client Version (2 bytes) + Random (32 bytes)
        client_version = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 34

        # Session ID length (1 byte)
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher Suites length (2 bytes)
        if offset + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        if offset + cipher_suites_len > len(payload):
            return None

        ciphers = []
        for i in range(0, cipher_suites_len, 2):
            val = struct.unpack("!H", payload[offset+i:offset+i+2])[0]
            if val not in GREASE_VALUES:
                ciphers.append(str(val))
        offset += cipher_suites_len

        # Compression Methods length (1 byte)
        if offset >= len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        server_name = None

        if offset + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + ext_total_len, len(payload))

            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[offset:offset+4])
                offset += 4

                if ext_type not in GREASE_VALUES:
                    extensions.append(str(ext_type))

                # Extension 0: Server Name Indication (SNI)
                if ext_type == 0 and offset + ext_len <= ext_end:
                    sni_data = payload[offset:offset+ext_len]
                    if len(sni_data) > 5:
                        sni_len = struct.unpack("!H", sni_data[3:5])[0]
                        server_name = sni_data[5:5+sni_len].decode('utf-8', errors='ignore')

                # Extension 10: Supported Groups (Elliptic Curves)
                elif ext_type == 10 and offset + ext_len <= ext_end:
                    curves_data = payload[offset:offset+ext_len]
                    if len(curves_data) >= 2:
                        curves_len = struct.unpack("!H", curves_data[:2])[0]
                        for i in range(2, min(2 + curves_len, len(curves_data)), 2):
                            curve_val = struct.unpack("!H", curves_data[i:i+2])[0]
                            if curve_val not in GREASE_VALUES:
                                elliptic_curves.append(str(curve_val))

                # Extension 11: EC Point Formats
                elif ext_type == 11 and offset + ext_len <= ext_end:
                    pts_data = payload[offset:offset+ext_len]
                    if len(pts_data) >= 1:
                        pts_len = pts_data[0]
                        for i in range(1, min(1 + pts_len, len(pts_data))):
                            ec_point_formats.append(str(pts_data[i]))

                offset += ext_len

        # Construct JA3 raw string: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_str = f"{client_version},{'-'.join(ciphers)},{'-'.join(extensions)},{'-'.join(elliptic_curves)},{'-'.join(ec_point_formats)}"
        ja3_hash = hashlib.md5(ja3_str.encode('utf-8')).hexdigest()

        return {
            "tls_version": client_version,
            "ja3_string": ja3_str,
            "ja3_hash": ja3_hash,
            "ciphers": ciphers,
            "extensions": extensions,
            "server_name": server_name
        }
    except Exception:
        return None


def parse_server_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses TLS ServerHello.
    Constructs JA3S raw string: SSLVersion,Cipher,Extensions and MD5 hash.
    """
    try:
        if len(payload) < 5:
            return None
        content_type, _, _ = struct.unpack("!BHH", payload[:5])
        if content_type != 22 or len(payload) < 9:
            return None
        
        # Handshake Type 2 (ServerHello)
        if payload[5] != 2:
            return None

        offset = 9
        if offset + 34 > len(payload):
            return None
        server_version = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 34  # version + random

        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Selected Cipher Suite (2 bytes)
        if offset + 2 > len(payload):
            return None
        cipher = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        # Compression (1 byte)
        offset += 1

        extensions = []
        if offset + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + ext_total_len, len(payload))
            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[offset:offset+4])
                offset += 4
                if ext_type not in GREASE_VALUES:
                    extensions.append(str(ext_type))
                offset += ext_len

        ja3s_str = f"{server_version},{cipher},{'-'.join(extensions)}"
        ja3s_hash = hashlib.md5(ja3s_str.encode('utf-8')).hexdigest()

        return {
            "tls_version": server_version,
            "cipher": cipher,
            "ja3s_string": ja3s_str,
            "ja3s_hash": ja3s_hash
        }
    except Exception:
        return None


def extract_pst_sequence(packets: List[Tuple[float, int, bool]], max_length: int = 10) -> List[int]:
    """
    Extracts Packet Size and Timing (PST) signed sequence:
    Signed packet lengths (+length for outbound/client->server, -length for inbound/server->client).
    Helps detect C2 burst patterns regardless of TLS extension randomization.
    """
    seq = []
    for _, length, is_outbound in packets[:max_length]:
        signed_len = length if is_outbound else -length
        seq.append(signed_len)
    # Pad to max_length with 0 if necessary
    while len(seq) < max_length:
        seq.append(0)
    return seq
