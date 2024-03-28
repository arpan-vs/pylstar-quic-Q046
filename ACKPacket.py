from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class ACKPacket(Packet):
    name = "ACKPacket"
    fields_desc = [
        XByteField("Public_Flags", 0xe3),
        StrFixedLenField("Version", "Q046", 4),
        XByteField("Connection_Id_Length", 0x50),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Packet_Number", string_to_ascii("00000001") , 4 ),

        # Message authentication hash
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii(""), 12),
        XByteField("Frame_Type", 0x40),
        XByteField("Largest_Acked", 2),
        LEShortField("Largest_Acked_Delta_Time", 45362),
        XByteField("First_Ack_Block_Length", 2),
        ByteField("Num_Timestamp", 0),
    ]
