
from events import *
from events.Events import SendFullCHLOEvent, SendInitialCHLOEvent
# s = Scapy()


def QuicInputMapper(alphabet, s):
    if alphabet=="InitialCHLO":
        x = s.send(SendInitialCHLOEvent())
    elif alphabet=="FullCHLO":
        x = s.send(SendFullCHLOEvent())
    else:
        pass
    return x


def QuicOutputMapper(data):
    output = ""
    if data[0] ^ 0x0c == 0:
        output = "SHLO"
    elif data[16+10: 16+10+3] == b'REJ':
        output = "REJ"
    else:
        output = "ERROR"
    return output