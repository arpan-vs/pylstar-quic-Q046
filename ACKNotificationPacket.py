from scapy.fields import *
from scapy.packet import Packet

from util.string_to_ascii import string_to_ascii


class AckNotificationPacket(Packet):
    """
    Holds the ack packet which will be send to the server.
    """
    name = "Ack Notification Packet"

    fields_desc = [
        XByteField("Public_Flags", 0xe3),
        StrFixedLenField("Version", "Q046", 4),
        XByteField("Connection_Id_Length", 0x50),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Packet_Number", string_to_ascii("00000001") , 4 )
    ]
