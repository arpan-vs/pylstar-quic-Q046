from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class PingPacket(Packet):
    name = "Ping Packet"

    fields_desc = [
        XByteField("Public_Flags", 0x18),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        LEShortField("Packet_Number", 768),

        # Message authentication hash
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii(""), 12),
    ]
