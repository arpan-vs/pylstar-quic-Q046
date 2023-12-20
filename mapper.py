
from events import *
from events.Events import SendFullCHLOEvent, SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent
# s = Scapy()


def QuicInputMapper(alphabet, s):
    if alphabet=="InitialCHLO":
        x = s.send(SendInitialCHLOEvent())
    elif alphabet=="FullCHLO":
        x = s.send(SendFullCHLOEvent())
    elif alphabet=="GET":
        x = s.send(SendGETRequestEvent())
    elif alphabet=="CLOSE":
        x = s.send(CloseConnectionEvent())
    else:
        pass
    return x


def QuicOutputMapper(data):
    output = ""
    if data == b"EXP":
        output = "EXP"
    elif data[6:10] == b"SHLO":
        output = "SHLO"
    elif data[34:37] == b'REJ':
        output = "REJ"
    elif data[34+8: 34+8+3] == b'REJ':
        output = "REJ"
    elif data == b"html":
        output = "HTTP"
    elif data == b"HTML":
        output = "HTTP"
    elif data == b"closed":
        output = "CLOSED"
    else:
        output = "ERROR"
    return output