import datetime
import time, os
import json
import random
from collections import Counter
from statistics import median, mean

from peewee import OperationalError
from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.all import Raw, bytes_hex
from scapy.sendrecv import send, sr
from scapy.supersocket import L3RawSocket

from ACKNotificationPacket import AckNotificationPacket
from ACKPacket import ACKPacket
from AEADPacketDynamic import AEADPacketDynamic, AEADFieldNames
from AEADRequestPacket import AEADRequestPacket
from DynamicCHLOPacket import DynamicCHLOPacket
from FramesProcessor import FramesProcessor
from FullCHLOPacket import FullCHLOPacket
from FullCHLOPacketNoPadding import FullCHLOPacketNoPadding
from PacketNumberInstance import PacketNumberInstance
from PingPacket import PingPacket
from QUIC_43_localhost import QUICHeader
from RejectionPacket import RejectionPacket
from SecondACKPacket import SecondACKPacket
from caching.CacheInstance import CacheInstance
from caching.SessionModel import SessionModel
from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from crypto.CryptoManager import CryptoManager
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, \
    ZeroRTTCHLOEvent, ResetEvent
from sniffer.sniffer import Sniffer
from util.NonDeterminismCatcher import NonDeterminismCatcher
from util.RespondDummy import RespondDummy
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii_old, string_to_ascii
import time
import logging
import os


# header lenght: 22 bytes
DPORT=443

class Scapy:

    TIMEOUT = 0.3263230323791504 * 5
    server_adress_token = b''
    server_nonce = b''
    server_connection_id = b''


    def __init__(self) -> None:
        currenttime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = 'log_{}.txt'.format(currenttime)
        #logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
        self.logger = logging.getLogger(__name__)

        dhke.set_up_my_keys()

    def reset(self, reset_server, reset_run=True):
        # also reset the server
        if reset_server:
            # remove the previous session
            CacheInstance.get_instance().remove_session_model()
            filename = str(time.time())
            open('resets/{}'.format(filename), 'a')
            time.sleep(8)

        if reset_run:
            # For the three times a command we do not want to remove the run events, only when there is a complete reset
            # which occurs after an iteration or after an explicit RESET command.

            self.run = ""
            # PacketNumberInstance.get_instance().reset()
            conn_id = random.getrandbits(64)
            SessionInstance.get_instance().shlo_received = False
            SessionInstance.get_instance().scfg = ""
            SessionInstance.get_instance().zero_rtt = False
            self.logger.info("Changing CID from {}".format(SessionInstance.get_instance().connection_id))
            SessionInstance.get_instance().connection_id_as_number = conn_id
            SessionInstance.get_instance().connection_id = str(format(conn_id, 'x').zfill(16))  # Pad to 16 chars
            self.logger.info("To {}".format(SessionInstance.get_instance().connection_id))

    def send_chlo(self, only_reset):
        # print("Only reset? {}".format(only_reset))
        self.reset(only_reset)

        # if only_reset:
        #     self.learner.respond("RESET")
        #     return

        # print(SessionInstance.get_instance().connection_id)

        # print("Sending CHLO")
        chlo = QUICHeader()
        conf.L3socket = L3RawSocket
        # cid_value = '30c2b2c2ac1bc2c0'
        # chlo.setfieldval('CID', string_to_ascii1(cid_value))
        # print(SessionInstance.get_instance().connection_id)

        chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        # chlo.setfieldval("Packet_Number", PacketNumberInstance.get_instance().get_next_packet_number())
        # print(PacketNumberInstance.get_instance())

        x = PacketNumberInstance.get_instance().get_next_packet_number()
        # print(x)
        chlo.setfieldval("Packet_Number", string_to_ascii(str("%02x" % x)))

        associated_data = extract_from_packet(chlo, end=14)
        body = extract_from_packet(chlo, start=26)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body)
        # print(message_authentication_hash)
        chlo.setfieldval('Message_Authentication_Hash', string_to_ascii(message_authentication_hash))
        
        # mac_val = b'\xf3\x3e\x04\xda\x45\xca\x71\x9c\x49\x9c\xf6\x58'
        # chlo.setfieldval('Message_Authentication_Hash', mac_val)

        # Store chlo for the key derivation
        SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo)
        # self.sniffer.add_observer(self)


        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=DPORT, sport=61250) / chlo
        ans, unans = sr(p,timeout=self.TIMEOUT)

        packet = bytes(ans[0][1][UDP][Raw])
        packet_type = packet[16+10: 16+10+3]
        self.server_adress_token = packet[16*5+10: 16*5+10+60]
        self.server_nonce = packet[16*9+6: 16*9+6+56]
        PROF = packet[16*12+14: 16*12+14+256]
        SCFG = packet[16*28+14: 16*28+14+175]
        RREJ = packet[16*39+13: 16*39+13+4]
        STTL = packet[16*40+1: 16*40+1+8]
        CRT = packet[16*40+9: 16*40+9+696]
        self.server_connection_id = packet[16*35+2: 16*35+2+16]
        PUBS = packet[16*36+6: 16*36+6+35]

        # print("Packet recieved : ",packet_type)
        return packet
        # SessionInstance.get_instance().peer_public_value = bytes.fromhex(PUBS[3:].hex())

        # # # print(ans[0][1][UDP][Raw].show())
        # print("STK : ",STK.hex())
        # print()
        # print("SNO : ",SNO.hex())
        # print()
        # print("PROF : ",PROF.hex())
        # print()
        # print("SCFG : ",SCFG.hex())
        # print()
        # print("RREJ : ",RREJ.hex())
        # print()
        # print("STTL : ",STTL.hex())
        # print()
        # print("CRT : ",CRT.hex())
# 20000079d756bbc5a0d69634141ba4327d547e91da42c84590855ea0308e0ca6baaa16 : value of REJ PUBS


    def send_full_chlo(self):

        fullchlo = FullCHLOPacket()



        fullchlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        fullchlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
        fullchlo.setfieldval('STK_Value', string_to_ascii(self.server_adress_token.hex()))
        fullchlo.setfieldval('SNO_Value', string_to_ascii(self.server_nonce.hex()))
        fullchlo.setfieldval('SCID_Value', string_to_ascii(self.server_connection_id.hex())) #incomplete


        epochtime = str(hex(int(time.time())))
        epoch = ''.join([epochtime[i:i+2] for i in range(0,len(epochtime),2)][1:][::-1])
        sORBIT = '0'*16
        randomString = bytes.hex(os.urandom(20))

        NONC = epoch + sORBIT + randomString

        fullchlo.setfieldval('NONC_Value',string_to_ascii(NONC))

        # Lets just create the public key for DHKE
        dhke.set_up_my_keys()

        x = PacketNumberInstance.get_instance().get_next_packet_number()
        # print(x)
        fullchlo.setfieldval("Packet_Number", string_to_ascii(str("%02x" % x)))

        fullchlo.setfieldval('PUBS_Value', string_to_ascii(SessionInstance.get_instance().public_values_bytes)) #incomplete

        # print('PUBS_Value', string_to_ascii(SessionInstance.get_instance().public_values_bytes))

        associated_data = extract_from_packet(fullchlo, end=10)
        body = extract_from_packet(fullchlo, start=22)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body)
        fullchlo.setfieldval('Message_Authentication_Hash', string_to_ascii(message_authentication_hash))

        conf.L3socket = L3RawSocket
        SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(fullchlo, start=31)   # CHLO from the CHLO tag, which starts at offset 26 (22 header + frame type + stream id + offset)

        # print("Send full CHLO")
        try:
            p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=DPORT, sport=61250) / fullchlo

            ans, unans = sr(p, timeout=self.TIMEOUT)

            
            packet = bytes(ans[0][1][UDP][Raw])

            return packet
        except:
            return [0]
        # a = AEADPacketDynamic(packet[0][1][1].payload.load)
        # a.parse()
        # print(">>>>>>>> Received packet with MAH: {}".format(a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)))

        # # Start key derixvation
        # SessionInstance.get_instance().div_nonce = a.get_field(AEADFieldNames.DIVERSIFICATION_NONCE)
        # SessionInstance.get_instance().message_authentication_hash = a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)
        # packet_number = a.get_field(AEADFieldNames.PACKET_NUMBER)
        # SessionInstance.get_instance().packet_number = packet_number
        # # print("Packet Number {}".format(packet_number))
        # SessionInstance.get_instance().largest_observed_packet_number = packet_number
        # SessionInstance.get_instance().associated_data = a.get_associated_data()
        # # print("Associated Data {}".format(SessionInstance.get_instance().associated_data))
        # ciphertext = split_at_nth_char(a.get_field(AEADFieldNames.ENCRYPTED_FRAMES))

        # # print("Received peer public value {}".format(SessionInstance.get_instance().peer_public_value))
        # dhke.generate_keys(SessionInstance.get_instance().peer_public_value,  SessionInstance.get_instance().shlo_received)
        # # SessionInstance.get_instance().packet_number = packet_number

        # # Process the streams
        # processor = FramesProcessor(ciphertext)
        # processor.process()


    def send(self, command, deterministic_repeat=False):
        try:
            if isinstance(command, ResetEvent):
                self.logger.info("Resetting received")
                return self.send_chlo(True)
            if isinstance(command, SendInitialCHLOEvent):
                self.logger.info("Sending CHLO")
                return self.send_chlo(False)
            elif isinstance(command, SendFullCHLOEvent):
                self.logger.info("Sending Full CHLO")
                return self.send_full_chlo()
            else:
                self.logger.info("Unknown command {}".format(command))
        except Exception as err:
            self.logger.exception(err)



# s = Scapy()
# print(s.send(SendInitialCHLOEvent()))
# print(s.send(SendFullCHLOEvent()))

# try:
#     operations = [(s.send_chlo, False), (s.send_full_chlo, True), (s.send_full_chlo_to_existing_connection, True), (s.send_encrypted_request, True), (s.close_connection, True), (s.reset, False)]
#     print("Starting now {}".format(time.time()))
#     for i in range(2):
#         random.shuffle(operations)
#         for operation, encrypted in operations:
#             print("PERFORMING OPERATION {}".format(operation))
#             operation()
#             print("FINISHED OPERATION {}".format(operation))
#             time.sleep(2)
# except:
#     print("Fail")
# # print("Done?!")
# times = []
# for i in tqdm(range(10)):
#     s.logger.info(">>>>>>>>>>>> Starting with round {}".format(i))
#     s.logger.info("Resetting")
#     s.send(ResetEvent())
#     start = time.time()
#     # s.send(SendInitialCHLOEvent())
#     # s.send(SendGETRequestEvent())
#     # s.send(CloseConnectionEvent())
#     times.append(time.time()-start)
#     s.send(CloseConnectionEvent())
#     s.logger.info("Currently at {} out of 10".format(i))

# times = sorted(times)
# s.logger.info("All execution times {}".format(times))
# s.logger.info("Median execution time is {}".format(median(times)))

# s.send(ResetEvent())
# s.send(ZeroRTTCHLOEvent())
#     s.send(SendGETRequestEvent())
#     s.send(ResetEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(SendGETRequestEvent())
# s.send(SendFullCHLOEvent())
# s.send(SendInitialCHLOEvent())
# s.send(SendInitialCHLOEvent())
# s.send(SendFullCHLOEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(SendGETRequestEvent())
# s.send(SendInitialCHLOEvent())
