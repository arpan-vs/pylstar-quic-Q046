import random
from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter, EmptyLetter
from pylstar.Word import Word


import socket
import time

from mapper import *
from PacketNumberInstance import PacketNumberInstance
from util.SessionInstance import SessionInstance


# s = Scapy()

class QUICServerKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, server_name, server, timeout=5):
        super(QUICServerKnowledgeBase, self).__init__()
        self._i = 1
        self.timeout = timeout
        self.server_name = server_name
        self.server = server

    def start(self):
        pass

    def stop(self):
        pass

    def start_target(self):
        pass

    def stop_target(self):
        pass

    def submit_word(self, word):

        if self.server==1:
            from socket_gquic_46 import Scapy
        else:
            pass
            # from socket_gquic_43_litespeed import Scapy

        self._logger.debug("Submiting word '{}' to the network target".format(word))

        output_letters = []

        print("-"*100)
        print("query : ",self._i)
        print("-"*100)
        # s = socket.socket()
        if self.server==1:
            s = Scapy("localhost")
        else:
            s = Scapy(self.server_name)
        # # Reuse the connection
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # s.settimeout(self.timeout)
        # s.connect((self.target_host, self.target_port))
        try:
            output_letters = [self._submit_letter(s, letter) for letter in word.letters]
            print(word.letters, output_letters)
        except:
            pass
        finally:
            # s.send(CloseConnectionEvent())
            del s
            # time.sleep(2)
            self._i+=1
            PacketNumberInstance.get_instance().reset()
            SessionInstance.reset()

        return Word(letters=output_letters)

    def _submit_letter(self, s, letter):
        output_letter = EmptyLetter()
        try:
            to_send = ''.join([symbol for symbol in letter.symbols])
            processed = QuicInputMapper(to_send, s)
            # time.sleep(0.2)
            # print(processed)
            output = QuicOutputMapper(processed)
            # print([to_send+ "/"+output])
            output_letter = Letter(output)
        except Exception as e:
            self._logger.error(e)

        return output_letter


    # def _send_and_receive(self, s, data):
    #     print('input:',data)
    #     s.sendall(data.encode("utf8"))
    #     time.sleep(0.1)
    #     outdata = s.recv(1024).decode("utf8").strip()
    #     print('output:',outdata)
    #     # outputlist.add(outdata)
    #     return outdata