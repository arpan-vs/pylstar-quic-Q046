from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter, EmptyLetter
from pylstar.Word import Word


import socket
import time

from mapper import *

from scapy_demo import Scapy

s = Scapy()

class QUICServerKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, target_host, target_port, timeout=5):
        super(QUICServerKnowledgeBase, self).__init__()
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout

    def start(self):
        pass

    def stop(self):
        pass

    def start_target(self):
        pass

    def stop_target(self):
        pass

    def submit_word(self, word):

        self._logger.debug("Submiting word '{}' to the network target".format(word))

        output_letters = []

        # s = socket.socket()
        s = Scapy()
        # # Reuse the connection
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # s.settimeout(self.timeout)
        # s.connect((self.target_host, self.target_port))
        try:
            output_letters = [self._submit_letter(s, letter) for letter in word.letters]
        finally:
            s.close_connection()

        return Word(letters=output_letters)

    def _submit_letter(self, s, letter):
        output_letter = EmptyLetter()
        try:
            to_send = ''.join([symbol for symbol in letter.symbols])
            output_letter = Letter(QuicInputMapper(to_send, s))
        except Exception as e:
            self._logger.error(e)

        return output_letter


    def _send_and_receive(self, s, data):
        print('input:',data)
        s.sendall(data.encode("utf8"))
        time.sleep(0.1)
        outdata = s.recv(1024).decode("utf8").strip()
        print('output:',outdata)
        # outputlist.add(outdata)
        return outdata