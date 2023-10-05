
from events import *
from events.Events import SendFullCHLOEvent, SendInitialCHLOEvent
from scapy_demo import Scapy

# s = Scapy()


def QuicInputMapper(alphabet, s):
    x = ""
    match alphabet:
        case "SendInitialCHLOEvent":
            x = s.send(SendInitialCHLOEvent())
        case "SendFullCHLOEvent":
            x = s.send(SendFullCHLOEvent())
        case default:
            pass
    return x


def QuicOutputMapper(data):
    match data:
        case default:
            pass
    return 