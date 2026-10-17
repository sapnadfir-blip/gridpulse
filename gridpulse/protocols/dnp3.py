import struct
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class DNP3FunctionCode(Enum):
    """Application Layer Function Codes."""
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    COLD_RESTART = 0x0D
    WARM_RESTART = 0x0E
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82
    UNKNOWN = 0xFF

class DNP3ParseError(Exception):
    """Exception raised for malformed DNP3 frames."""
    pass

# Precomputed CRC-16 lookup table for DNP3 (Polynomial 0x3D65, bit-reversed to 0xA6BC)
_DNP3_CRC_TABLE = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = (_crc >> 1) ^ 0xA6BC
        else:
            _crc >>= 1
    _DNP3_CRC_TABLE.append(_crc)

def calculate_dnp3_crc(data: bytes) -> int:
    """Calculates DNP3 CRC-16 for the given data."""
    crc = 0x0000
    for byte in data:
        crc = (crc >> 8) ^ _DNP3_CRC_TABLE[(crc ^ byte) & 0xFF]
    return (~crc) & 0xFFFF

@dataclass
class DNP3ObjectHeader:
    """Represents a DNP3 Application Layer Object Header."""
    group: int
    variation: int
    qualifier: int
    range_data: bytes = b''
    object_data: bytes = b''

    def __str__(self) -> str:
        return f"Object(G{self.group}V{self.variation}, Qual: 0x{self.qualifier:02X})"

@dataclass
class DNP3Application:
    """Represents a DNP3 Application Layer segment."""
    app_control: int
    function_code: DNP3FunctionCode
    objects: List[DNP3ObjectHeader] = field(default_factory=list)

    @property
    def fir(self) -> bool: return bool(self.app_control & 0x80)
    @property
    def fin(self) -> bool: return bool(self.app_control & 0x40)
    @property
    def con(self) -> bool: return bool(self.app_control & 0x20)
    @property
    def uns(self) -> bool: return bool(self.app_control & 0x10)
    @property
    def seq(self) -> int: return self.app_control & 0x0F

    def __str__(self) -> str:
        objs = ", ".join(str(o) for o in self.objects)
        return (f"App(FIR={self.fir}, FIN={self.fin}, CON={self.con}, UNS={self.uns}, "
                f"SEQ={self.seq}, FUNC={self.function_code.name}, OBJS=[{objs}])")

@dataclass
class DNP3Transport:
    """Represents a DNP3 Transport Layer segment."""
    transport_header: int
    payload: bytes

    @property
    def fin(self) -> bool: return bool(self.transport_header & 0x80)
    @property
    def fir(self) -> bool: return bool(self.transport_header & 0x40)
    @property
    def seq(self) -> int: return self.transport_header & 0x3F

    def __str__(self) -> str:
        return f"Transport(FIR={self.fir}, FIN={self.fin}, SEQ={self.seq}, len={len(self.payload)})"

@dataclass
class DNP3DataLink:
    """Represents a DNP3 Data Link Layer (FT3) frame."""
    length: int
    control: int
    destination: int
    source: int
    payload: bytes

    @property
    def dir(self) -> bool: return bool(self.control & 0x80)
    @property
    def prm(self) -> bool: return bool(self.control & 0x40)
    @property
    def fcb(self) -> bool: return bool(self.control & 0x20)
    @property
    def fcv(self) -> bool: return bool(self.control & 0x10)
    @property
    def func_code(self) -> int: return self.control & 0x0F

    def __str__(self) -> str:
        return (f"Link(DIR={self.dir}, PRM={self.prm}, FC={self.func_code}, "
                f"SRC={self.source}, DST={self.destination}, len={self.length})")

@dataclass
class DNP3Frame:
    """Represents a complete DNP3 message parsed from raw bytes."""
    data_link: DNP3DataLink
    transport: Optional[DNP3Transport] = None
    application: Optional[DNP3Application] = None

    def __str__(self) -> str:
        res = [str(self.data_link)]
        if self.transport:
            res.append(str(self.transport))
        if self.application:
            res.append(str(self.application))
        return " | ".join(res)

    @classmethod
    def parse(cls, raw_bytes: bytes) -> 'DNP3Frame':
        """
        Parses a raw DNP3 byte sequence into a DNP3Frame object.
        Gracefully handles CRC verification, data block reassembly, and malformed frames.
        """
        if len(raw_bytes) < 10:
            raise DNP3ParseError("Frame too short for DNP3 Data Link Header")

        # 1. Validate Start Bytes
        if raw_bytes[0] != 0x05 or raw_bytes[1] != 0x64:
            raise DNP3ParseError(f"Invalid start bytes: {raw_bytes[:2].hex()}")

        # 2. Validate Header CRC
        header_crc = struct.unpack('<H', raw_bytes[8:10])[0]
        if calculate_dnp3_crc(raw_bytes[:8]) != header_crc:
            raise DNP3ParseError("Data Link Header CRC mismatch")

        length = raw_bytes[2]
        if length < 5:
            raise DNP3ParseError("Invalid Data Link Length (must be at least 5)")

        control = raw_bytes[3]
        destination = struct.unpack('<H', raw_bytes[4:6])[0]
        source = struct.unpack('<H', raw_bytes[6:8])[0]

        # 3. Transport Layer Reassembly (Extract Data Blocks)
        user_data_len = length - 5
        offset = 10
        user_data = bytearray()
        remaining = user_data_len

        while remaining > 0:
            chunk_size = min(16, remaining)
            if len(raw_bytes) < offset + chunk_size + 2:
                raise DNP3ParseError("Unexpected end of frame in data blocks")
            
            chunk = raw_bytes[offset : offset + chunk_size]
            chunk_crc = struct.unpack('<H', raw_bytes[offset + chunk_size : offset + chunk_size + 2])[0]
            
            if calculate_dnp3_crc(chunk) != chunk_crc:
                raise DNP3ParseError(f"Data chunk CRC mismatch at offset {offset}")
                
            user_data.extend(chunk)
            offset += chunk_size + 2
            remaining -= chunk_size

        data_link = DNP3DataLink(
            length=length,
            control=control,
            destination=destination,
            source=source,
            payload=bytes(user_data)
        )

        frame = cls(data_link=data_link)

        # 4. Transport & Application Layer Parsing
        if len(user_data) > 0:
            transport_header = user_data[0]
            transport_payload = user_data[1:]
            frame.transport = DNP3Transport(
                transport_header=transport_header,
                payload=transport_payload
            )

            # Note: DNP3 transport payload might span multiple frames. We parse application
            # if we see a valid application header (assuming un-fragmented or assembled).
            if len(transport_payload) > 0:
                app_control = transport_payload[0]
                if len(transport_payload) > 1:
                    try:
                        func_code = DNP3FunctionCode(transport_payload[1])
                    except ValueError:
                        func_code = DNP3FunctionCode.UNKNOWN
                    
                    frame.application = DNP3Application(
                        app_control=app_control,
                        function_code=func_code
                    )

                    # Simple Object Header Parsing Loop
                    app_offset = 2
                    while app_offset < len(transport_payload):
                        if app_offset + 3 > len(transport_payload):
                            break  # Avoid out-of-bounds
                            
                        group = transport_payload[app_offset]
                        variation = transport_payload[app_offset + 1]
                        qualifier = transport_payload[app_offset + 2]
                        
                        app_offset += 3
                        
                        # Basic range parsing logic based on qualifier code
                        qualifier_code = qualifier & 0x0F
                        range_len = 0
                        
                        if qualifier_code == 0x00:
                            range_len = 2 # 1-octet start/stop
                        elif qualifier_code == 0x01:
                            range_len = 4 # 2-octet start/stop
                        elif qualifier_code in (0x07, 0x08, 0x09):
                            range_len = 1 # 1-octet count
                            
                        # Extract range data if present
                        if app_offset + range_len <= len(transport_payload):
                            range_data = transport_payload[app_offset : app_offset + range_len]
                            app_offset += range_len
                            
                            frame.application.objects.append(
                                DNP3ObjectHeader(
                                    group=group, 
                                    variation=variation, 
                                    qualifier=qualifier, 
                                    range_data=range_data
                                )
                            )
                        
                        # Note: In a complete parser we would advance over object data here
                        # For now we stop parsing after the first object to prevent infinite loops
                        # on unsupported qualifier types.
                        break
        
        return frame
