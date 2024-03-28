
from events import *
from events.Events import *
# s = Scapy()


def QuicInputMapper(alphabet, s):
    match alphabet:
        case "InitialCHLO":
            x = s.send(SendInitialCHLOEvent())
        case "FullCHLO":
            x = s.send(SendFullCHLOEvent())
        case "EmptyCertHashFullCHLO":
            x = s.send(SendEmptyCERTHashFullCHLOEvent())
        case "RemovedCertHashFullCHLO":
            x = s.send(SendRemovedCERTHashFullCHLOEvent())
        case "GET":
            x = s.send(SendGETRequestEvent())
        case "CLOSE":
            x = s.send(CloseConnectionEvent())
        case "ZeroRTT":
            x = s.send(SendZeroRTTCHLOEvent())
        case "EmptyCertHashZeroRTT":
            x = s.send(SendEmptyCERTHashZeroRTTCHLOEvent())
        case "RemovedCertHashZeroRTT":
            x = s.send(SendRemovedCERTHashZeroRTTCHLOEvent())
        case "InvalidInitialCHLO":
            x = s.send(SendInvalidInitialCHLOEvent())
        case "InvalidFullCHLO":
            x = s.send(SendInvalidFullCHLOEvent())
        case "InvalidGET":
            x = s.send(SendInvalidGETRequestEvent())
        case "InvalidCLOSE":
            x = s.send(InvalidCloseConnectionEvent())
        case "InvalidZeroRTT":
            x = s.send(SendInvalidZeroRTTCHLOEvent())
        case default:
            pass
    return x

    # mapping = {

    #     "InitialCHLO": SendInitialCHLOEvent(),
    #     "FullCHLO": SendFullCHLOEvent(),
    #     "EmptyCertHashFullCHLO": SendEmptyCERTHashFullCHLOEvent(),
    #     "RemovedCertHashFullCHLO": SendRemovedCERTHashFullCHLOEvent(),
    #     "GET": SendGETRequestEvent(),
    #     "CLOSE": CloseConnectionEvent(),
    #     "ZeroRTT": SendZeroRTTCHLOEvent(),
    #     "EmptyCertHashZeroRTT": SendEmptyCERTHashZeroRTTCHLOEvent(),
    #     "RemovedCertHashZeroRTT": SendRemovedCERTHashZeroRTTCHLOEvent(),
    #     "InvalidInitialCHLO": SendInvalidInitialCHLOEvent(),
    #     "InvalidFullCHLO": SendInvalidFullCHLOEvent(),
    #     "InvalidGET": SendInvalidGETRequestEvent(),
    #     "InvalidCLOSE": InvalidCloseConnectionEvent(),
    #     "InvalidZeroRTT": SendInvalidZeroRTTCHLOEvent(),
    # }

    # return s.send(mapping[alphabet])


def QuicOutputMapper(data):
    output = ""
    if data == b"EXP":
        output = "EXP"
    elif data == b"ERROR":
        output = "ERROR"
    elif data == b"closed":
        output = "CLOSED"
    elif data == b"html":
        output = "HTTP"
    elif data == b"HTML":
        output = "HTTP"
    elif data == b"PRST":
        output = "PRST"
    elif data == b"SHLO":
        output = "SHLO"
    elif data == b'REJ':
        output = "REJ"
    else:
        output = "ERROR"
    return output