from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class SecondACKPacket(Packet):
    name = "ACKPacket 2"
    fields_desc = [
        XByteField("Public_Flags", 0x19),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        PacketField("Version", "Q039", "Q039"),
        LEShortField("Packet_Number", 768),

        # Message authentication hash
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii("08c9ea3eed281184a3fd65a5"), 12),
        XByteField("Frame_Type", 0x40),
        ByteField("Largest_Acked", 2),
        LEShortField("Largest_Acked_Delta_Time", 1108),
        ByteField("First_Ack_Block_Length", 2),
        ByteField("Num_Timestamp", 0),
    ]