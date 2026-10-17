import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Any, Union
import enum

class GOOSEParseError(Exception):
    """Exception raised for malformed GOOSE frames."""
    pass

def mac_to_bytes(mac_str: str) -> bytes:
    """Convert MAC string (e.g. '01:0c:cd:01:00:00') to bytes."""
    try:
        return bytes(int(x, 16) for x in mac_str.split(':'))
    except Exception as e:
        raise ValueError(f"Invalid MAC address string: {mac_str}") from e

def bytes_to_mac(mac_bytes: bytes) -> str:
    """Convert MAC bytes to string."""
    if len(mac_bytes) != 6:
        raise ValueError("MAC address must be 6 bytes")
    return ':'.join(f"{b:02x}" for b in mac_bytes)

# --- BER-TLV Utilities ---

def encode_length(length: int) -> bytes:
    """Encode BER length."""
    if length < 128:
        return bytes([length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')
        return bytes([0x80 | len(length_bytes)]) + length_bytes

def decode_length(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode BER length. Returns (length, bytes_consumed)."""
    if offset >= len(data):
        raise GOOSEParseError("Unexpected end of data when reading length")
    
    first_byte = data[offset]
    if first_byte < 128:
        return first_byte, 1
    
    num_bytes = first_byte & 0x7F
    if num_bytes == 0:
        raise GOOSEParseError("Indefinite length form not supported")
    if offset + 1 + num_bytes > len(data):
        raise GOOSEParseError("Unexpected end of data reading extended length")
    
    length = int.from_bytes(data[offset+1 : offset+1+num_bytes], byteorder='big')
    return length, 1 + num_bytes

def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a BER TLV."""
    return bytes([tag]) + encode_length(len(value)) + value

def decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Decode a BER TLV. Returns (tag, value_bytes, bytes_consumed)."""
    if offset >= len(data):
        raise GOOSEParseError("Unexpected end of data reading tag")
    
    tag = data[offset]
    length, len_bytes = decode_length(data, offset + 1)
    
    value_start = offset + 1 + len_bytes
    if value_start + length > len(data):
        raise GOOSEParseError(f"TLV length {length} exceeds available data")
        
    value = data[value_start : value_start + length]
    return tag, value, 1 + len_bytes + length

def encode_integer(val: int) -> bytes:
    """Encode an integer (two's complement)."""
    if val == 0:
        return bytes([0x00])
    bit_length = val.bit_length()
    if val > 0 and (val & (1 << (bit_length - 1))):
        bit_length += 1
    elif val < 0:
        bit_length += 1
    byte_length = (bit_length + 7) // 8
    if byte_length == 0:
        byte_length = 1
    return val.to_bytes(byte_length, byteorder='big', signed=True)

def decode_integer(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big', signed=True)

def decode_unsigned(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big', signed=False)

def encode_boolean(val: bool) -> bytes:
    return bytes([0x01 if val else 0x00])

def decode_boolean(data: bytes) -> bool:
    if not data:
        raise GOOSEParseError("Empty boolean")
    return data[0] != 0

def encode_visible_string(s: str) -> bytes:
    return s.encode('ascii')

def decode_visible_string(data: bytes) -> str:
    return data.decode('ascii', errors='replace')

def encode_utc_time(sec: int, frac: int = 0, quality: int = 0) -> bytes:
    """Encode UtcTime (8 bytes)."""
    b_sec = sec.to_bytes(4, byteorder='big')
    b_frac = frac.to_bytes(3, byteorder='big')
    b_qual = bytes([quality])
    return b_sec + b_frac + b_qual

def decode_utc_time(data: bytes) -> Tuple[int, int, int]:
    """Decode UtcTime (8 bytes). Returns (seconds, fraction, quality)."""
    if len(data) != 8:
        raise GOOSEParseError(f"UtcTime must be 8 bytes, got {len(data)}")
    sec = int.from_bytes(data[0:4], byteorder='big')
    frac = int.from_bytes(data[4:7], byteorder='big')
    qual = data[7]
    return sec, frac, qual

def decode_float(data: bytes) -> float:
    if len(data) != 5:
        raise GOOSEParseError(f"Float must be 5 bytes, got {len(data)}")
    # Exponent width is data[0], we ignore it and parse IEEE 754 float
    return struct.unpack('>f', data[1:5])[0]

def encode_float(val: float) -> bytes:
    # Exponent width = 8 (typical for single precision)
    return bytes([8]) + struct.pack('>f', val)

def decode_bit_string(data: bytes) -> bytes:
    if len(data) < 1:
        return b""
    # First byte is padding length, ignored for simplicity
    return data[1:]

def encode_bit_string(data: bytes, padding: int = 0) -> bytes:
    return bytes([padding]) + data

# --- Data Structures ---

@dataclass
class EthernetHeader:
    dest_mac: str
    src_mac: str
    vlan_tci: Optional[int] = None
    ethertype: int = 0x88B8

    def has_vlan(self) -> bool:
        return self.vlan_tci is not None

    def is_multicast(self) -> bool:
        return self.dest_mac.lower().startswith("01:0c:cd:01")

    @classmethod
    def parse(cls, data: bytes) -> Tuple['EthernetHeader', int]:
        if len(data) < 14:
            raise GOOSEParseError("Frame too short for Ethernet header")
        
        dest_mac = bytes_to_mac(data[0:6])
        src_mac = bytes_to_mac(data[6:12])
        
        ethertype = int.from_bytes(data[12:14], byteorder='big')
        offset = 14
        
        vlan_tci = None
        if ethertype == 0x8100:
            if len(data) < 18:
                raise GOOSEParseError("Frame too short for VLAN tag")
            vlan_tci = int.from_bytes(data[14:16], byteorder='big')
            ethertype = int.from_bytes(data[16:18], byteorder='big')
            offset = 18
            
        if ethertype != 0x88B8:
            raise GOOSEParseError(f"Invalid EtherType for GOOSE: 0x{ethertype:04X}")
            
        return cls(dest_mac=dest_mac, src_mac=src_mac, vlan_tci=vlan_tci, ethertype=ethertype), offset

    def build(self) -> bytes:
        b = mac_to_bytes(self.dest_mac) + mac_to_bytes(self.src_mac)
        if self.vlan_tci is not None:
            b += struct.pack('>HH', 0x8100, self.vlan_tci)
        b += struct.pack('>H', self.ethertype)
        return b

@dataclass
class GOOSEHeader:
    appid: int
    length: int
    reserved1: int = 0
    reserved2: int = 0

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Tuple['GOOSEHeader', int]:
        if offset + 8 > len(data):
            raise GOOSEParseError("Data too short for GOOSE header")
        
        appid, length, r1, r2 = struct.unpack('>HHHH', data[offset:offset+8])
        return cls(appid=appid, length=length, reserved1=r1, reserved2=r2), offset + 8

    def build(self) -> bytes:
        return struct.pack('>HHHH', self.appid, self.length, self.reserved1, self.reserved2)

@dataclass
class GOOSEPDU:
    gocbRef: str
    timeAllowedToLive: int
    datSet: str
    goID: str
    t: Tuple[int, int, int]
    stNum: int
    sqNum: int
    simulation: bool
    confRev: int
    ndsCom: bool
    numDatSetEntries: int
    allData: List[Any]

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'GOOSEPDU':
        tag, pdu_data, _ = decode_tlv(data, offset)
        if tag != 0x61:
            raise GOOSEParseError(f"Invalid GOOSE PDU tag: 0x{tag:02X}, expected 0x61")

        pdu_offset = 0
        fields = {}
        
        while pdu_offset < len(pdu_data):
            ftag, fval, fconsumed = decode_tlv(pdu_data, pdu_offset)
            pdu_offset += fconsumed
            
            if ftag == 0x80: fields['gocbRef'] = decode_visible_string(fval)
            elif ftag == 0x81: fields['timeAllowedToLive'] = decode_integer(fval)
            elif ftag == 0x82: fields['datSet'] = decode_visible_string(fval)
            elif ftag == 0x83: fields['goID'] = decode_visible_string(fval)
            elif ftag == 0x84: fields['t'] = decode_utc_time(fval)
            elif ftag == 0x85: fields['stNum'] = decode_integer(fval)
            elif ftag == 0x86: fields['sqNum'] = decode_integer(fval)
            elif ftag == 0x87: fields['simulation'] = decode_boolean(fval)
            elif ftag == 0x88: fields['confRev'] = decode_integer(fval)
            elif ftag == 0x89: fields['ndsCom'] = decode_boolean(fval)
            elif ftag == 0x8A: fields['numDatSetEntries'] = decode_integer(fval)
            elif ftag == 0xAB:
                fields['allData'] = cls._parse_alldata(fval)
            else:
                pass
                
        required_keys = ['gocbRef', 'timeAllowedToLive', 'datSet', 'goID', 't', 
                         'stNum', 'sqNum', 'simulation', 'confRev', 'ndsCom', 
                         'numDatSetEntries', 'allData']
        for k in required_keys:
            if k not in fields:
                raise GOOSEParseError(f"Missing required GOOSE PDU field: {k}")

        return cls(**fields)

    @classmethod
    def _parse_alldata(cls, data: bytes) -> List[Any]:
        items = []
        offset = 0
        while offset < len(data):
            tag, val, consumed = decode_tlv(data, offset)
            offset += consumed
            
            if tag == 0x83: items.append(decode_boolean(val))
            elif tag == 0x84: items.append(decode_bit_string(val))
            elif tag == 0x85: items.append(decode_integer(val))
            elif tag == 0x86: items.append(decode_unsigned(val))
            elif tag == 0x87: items.append(decode_float(val))
            elif tag == 0x8A: items.append(decode_visible_string(val))
            elif tag == 0x91: items.append(decode_utc_time(val))
            elif tag == 0xA2: items.append(cls._parse_alldata(val))
            else:
                items.append(val)
        return items

    def _build_alldata(self) -> bytes:
        b = b""
        def _build_items(items):
            res = b""
            for item in items:
                if isinstance(item, bool):
                    res += encode_tlv(0x83, encode_boolean(item))
                elif isinstance(item, int):
                    res += encode_tlv(0x85, encode_integer(item))
                elif isinstance(item, float):
                    res += encode_tlv(0x87, encode_float(item))
                elif isinstance(item, str):
                    res += encode_tlv(0x8A, encode_visible_string(item))
                elif isinstance(item, tuple) and len(item) == 3:
                    res += encode_tlv(0x91, encode_utc_time(*item))
                elif isinstance(item, bytes):
                    res += encode_tlv(0x84, encode_bit_string(item))
                elif isinstance(item, list):
                    res += encode_tlv(0xA2, _build_items(item))
            return res
        return encode_tlv(0xAB, _build_items(self.allData))

    def build(self) -> bytes:
        pdu_data = b""
        pdu_data += encode_tlv(0x80, encode_visible_string(self.gocbRef))
        pdu_data += encode_tlv(0x81, encode_integer(self.timeAllowedToLive))
        pdu_data += encode_tlv(0x82, encode_visible_string(self.datSet))
        pdu_data += encode_tlv(0x83, encode_visible_string(self.goID))
        pdu_data += encode_tlv(0x84, encode_utc_time(*self.t))
        pdu_data += encode_tlv(0x85, encode_integer(self.stNum))
        pdu_data += encode_tlv(0x86, encode_integer(self.sqNum))
        pdu_data += encode_tlv(0x87, encode_boolean(self.simulation))
        pdu_data += encode_tlv(0x88, encode_integer(self.confRev))
        pdu_data += encode_tlv(0x89, encode_boolean(self.ndsCom))
        pdu_data += encode_tlv(0x8A, encode_integer(self.numDatSetEntries))
        pdu_data += self._build_alldata()
        
        return encode_tlv(0x61, pdu_data)


@dataclass
class GOOSEFrame:
    eth_header: EthernetHeader
    goose_header: GOOSEHeader
    goose_pdu: GOOSEPDU

    @classmethod
    def parse(cls, data: bytes) -> 'GOOSEFrame':
        eth, offset = EthernetHeader.parse(data)
        ghdr, offset2 = GOOSEHeader.parse(data, offset)
        
        pdu_data = data[offset2:offset + ghdr.length]
        pdu = GOOSEPDU.parse(pdu_data)
        
        return cls(eth_header=eth, goose_header=ghdr, goose_pdu=pdu)

    def build(self) -> bytes:
        pdu_bytes = self.goose_pdu.build()
        self.goose_header.length = 8 + len(pdu_bytes)
        
        return self.eth_header.build() + self.goose_header.build() + pdu_bytes

    def is_multicast(self) -> bool:
        return self.eth_header.is_multicast()

    def has_vlan(self) -> bool:
        return self.eth_header.has_vlan()

    def trip_active(self) -> bool:
        """Check if any boolean value in allData is True (often indicates a trip signal)."""
        def _check_bools(items: List[Any]) -> bool:
            for item in items:
                if isinstance(item, bool) and item is True:
                    return True
                elif isinstance(item, list):
                    if _check_bools(item):
                        return True
            return False
        return _check_bools(self.goose_pdu.allData)

    def __str__(self) -> str:
        return (f"GOOSEFrame(stNum={self.goose_pdu.stNum}, "
                f"sqNum={self.goose_pdu.sqNum}, "
                f"goID='{self.goose_pdu.goID}', "
                f"trip={self.trip_active()})")

    def __repr__(self) -> str:
        return self.__str__()
