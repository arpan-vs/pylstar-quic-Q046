import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from donna25519 import PrivateKey, PublicKey

from caching.SessionModel import SessionModel
from util.SessionInstance import SessionInstance


class dhke:

    @staticmethod
    def set_up_my_keys():
        """
        Sets up my part for the DHKE
        :return:
        """
        private_key = PrivateKey()
        my_public_key = PublicKey((private_key.get_public()).public)
        SessionInstance.get_instance().public_value = my_public_key
        SessionInstance.get_instance().public_values_bytes = my_public_key.public.hex()
        SessionInstance.get_instance().private_value = private_key.private

    @staticmethod
    def generate_keys(peer_public_value: bytes, forward_secure=False, logger=None):
        """
        Method that implements Diffie Hellman with Curve25519
        Receives the public value and chooses a secret value such that it is able
        to compute the shared session key ( * In this application, the output of DHKE is used
        with the salt as input for the HKDF).
        :param forward_secure:
        :param peer_public_value as bytes
        :return:
        """
        # 1. Load my key
        private_key = PrivateKey(secret=SessionInstance.get_instance().private_value)

        # 2. compute the shared secret
        if len(peer_public_value) != 32:
            raise Exception("Invalid length of peer public value, should be 32 bytes received {} bytes".format(len(peer_public_value)))

        shared_key = private_key.do_exchange(PublicKey(peer_public_value))

        # 3. Apply the kdf
        info = dhke.generate_info(forward_secure)
        salt = bytes.fromhex(SessionInstance.get_instance().client_nonce) # Fixed client nonce
        if forward_secure or SessionInstance.get_instance().zero_rtt:
            salt += bytes.fromhex(SessionInstance.get_instance().server_nonce)  # Appended with dynamic server nonce
        else:
            salt = salt + bytes.fromhex(SessionInstance.get_instance().server_nonce)

        derived_shared_key = dhke.perform_hkdf(salt, shared_key, info, forward_secure)

        if forward_secure:
            SessionInstance.get_instance().final_keys = derived_shared_key
        else:
            SessionInstance.get_instance().initial_keys = derived_shared_key

        SessionInstance.get_instance().keys = derived_shared_key
        return derived_shared_key

    @staticmethod
    def perform_hkdf(salt, shared_key, info, forward_secure=False):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=40,  # 2 * keyLen (=16) + 2 * 4
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_key)

        keys = {
            'key1': derived_key[:16],   # my key
            'key2': derived_key[16:32], # other key
            'iv1': derived_key[32:32+4],# my iv
            'iv2': derived_key[32+4:]   # other iv
        }
        return keys

    @staticmethod
    def diversify(key: bytes, iv: bytes, div_nonce: bytes):
        secret = key + iv

        diversified_key = HKDF(
            algorithm=hashes.SHA256(),
            length=20,  # 2 * keyLen (=16) + 2 * 4
            salt=div_nonce,
            info=bytes("QUIC key diversification", encoding='utf-8'),
            backend=default_backend()
        ).derive(secret)

        return {
            'diversified_key': diversified_key[:16],
            'diversified_iv': diversified_key[16:]
        }

    @staticmethod
    def print_like_go(info):
        info_as_string = "".join(map(chr, info))
        info_quic_style = [ord(c) for c in info_as_string]
        return info_quic_style

    @staticmethod
    def generate_info(forward_secure=True):
        info = b""
        if forward_secure:
            info += "QUIC forward secure key expansion".encode('utf-8')
        else:
            info += "QUIC key expansion".encode('utf-8')
        info += b"\x00"
        try:
            info += bytes.fromhex(SessionInstance.get_instance().connection_id)
        except ValueError:
            print("Error in connection id? {}".format(SessionInstance.get_instance().connection_id))
            return

        info += bytes.fromhex(SessionInstance.get_instance().chlo)

        info += bytes.fromhex(SessionInstance.get_instance().scfg)

        info += bytes.fromhex(SessionInstance.get_instance().cert)

        return info

    @staticmethod
    def init_golang_byte_array_from_string(input):
        input = input.replace("[", "{")
        input = input.replace("]", "}")
        input = input.replace(" ", ", ")

    @staticmethod
    def compare_infos(own_info, quic_info):
        # Transform quic string to array
        quic_info_as_array = quic_info.split(" ")

        equal = True
        for own_idx, own_char in enumerate(own_info):
            for quic_idx, quic_char in enumerate(quic_info_as_array):
                if own_idx == quic_idx:
                    if not str(own_char) == quic_char:
                        equal = False
                        break

    @staticmethod
    def quic_go_byte_array_print_to_python_array(input):
        """
        Converts a printed byte array from GoLang to a Python byte array
        :param input:
        :return:
        """
        input = input.replace("[", "")
        input = input.replace("]", "")
        output = input.split(" ")
        output = ["%02x" % int(x) for x in output]
        return output