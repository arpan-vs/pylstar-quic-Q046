
from events import *
from events.Events import SendFullCHLOEvent, SendInitialCHLOEvent
# s = Scapy()


def QuicInputMapper(alphabet, s):
    if alphabet=="InitialCHLO":
        x = s.send(SendInitialCHLOEvent())
    elif alphabet=="FullCHLO":
        x = s.send(SendFullCHLOEvent())
    #elif alphabet=="ZERO-RTT":
     #   x = s.send(ZeroRTTCHLOEvent())
    else:
        pass
    return x


def QuicOutputMapper(data):
    output = ""
    print("\n***data in mapper***",data[6:10])
    if data == b"EXP":
        output = "EXP"
    elif data[6:10] == b"SHLO":
        output = "SHLO"
    elif data[34:37] == b'REJ':
        output = "REJ"
    elif data[34+8: 34+8+3] == b'REJ':
        output = "REJ"
    else:
        output = "ERROR"
    return output
    # if data[0] ^ 0x0c == 0:
    #     output = "SHLO"
    # elif data[16+10: 16+10+3] == b'REJ':
    #     output = "REJ"
    # else:
    #     output = "ERROR"
    # return output