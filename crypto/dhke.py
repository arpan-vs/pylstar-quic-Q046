from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from util.SessionInstance import SessionInstance


class dhke:

    @staticmethod
    def generate_keys(peer_public_value):
        """
        Method that implements Diffie Hellman with Curve25519
        Receives the public value and chooses a secret value such that it is able
        to compute the shared session key ( * In this application, the output of DHKE is used
        with the salt as input for the HKDF).
        :return:
        """
        # 1. Choose a private key
        if SessionInstance.get_instance().private_value is None or SessionInstance.get_instance().public_value == "":
            private_key = X25519PrivateKey.generate()
            my_public_key = private_key.public_key().public_bytes()
            SessionInstance.get_instance().public_value = my_public_key
            print("My public key {}".format(my_public_key))
            SessionInstance.get_instance().private_value = private_key
        else:
            private_key = SessionInstance.get_instance().private_value
            my_public_key = SessionInstance.get_instance().public_value

        # 2. get the value from the other party
        # peer_public_key_generated = X25519PrivateKey.generate().public_key()
        # print(peer_public_key_generated.public_bytes())
        # peer_public_value = X25519PublicKey.from_public_bytes(b'\x29\xfd\x1f\xbf\xc3\x40\xa5\x63\x0f\xae\x3b\xe5\x4d\x28\xea\x5c\x82\xc2\x56\x01\xcf\x3e\xed\xb5\x3d\x34\x6a\xd8\x82\x2b\x64\x4a')

        # 3. compute the shared secret
        shared_key = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public_value))
        dhke.print_like_go(shared_key)

        # 4. Apply the kdf
        info = dhke.generate_info()
        salt = bytes.fromhex("5ac349e90091b5556f1a3c52eb57f92c12640e876e26ab2601c02b2a32f54830") # Fixed client nonce
        salt += SessionInstance.get_instance().server_nonce # Appended with dynamic server nonce

        derived_shared_key = dhke.perform_hkdf(salt, shared_key, info)

        SessionInstance.get_instance().shared_key = derived_shared_key
        return derived_shared_key

    @staticmethod
    def perform_hkdf(salt, shared_key, info):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=40,  # 2 * keyLen (=16) + 2 * 4
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_key)
        print("Derived shared key for AES: ")
        dhke.print_like_go(derived_key)
        return derived_key

    @staticmethod
    def print_like_go(info):
        info_as_string = "".join(map(chr, info))
        info_quic_style = [ord(c) for c in info_as_string]
        print(info_quic_style)
        return info_quic_style

    @staticmethod
    def generate_info(forward_secure=False):
        info = b""
        # Fixed label
        if forward_secure:
            info += "QUIC key expansion".encode('utf-8')
        else:
            info += "QUIC forward secure key expansion".encode('utf-8')
        info += b"\x00"
        conn_id = 9299818721181127895
        info += conn_id.to_bytes(8, byteorder='big')

        info += SessionInstance.get_instance().chlo

        info += SessionInstance.get_instance().scfg

        info += SessionInstance.get_instance().cert

        return info

    @staticmethod
    def init_golang_byte_array_from_string(input):
        input = input.replace("[", "{")
        input = input.replace("]", "}")
        input = input.replace(" ", ", ")
        print(input)

    @staticmethod
    def compare_infos(own_info, quic_info):
        # Transform quic string to array
        quic_info_as_array = quic_info.split(" ")
        print(quic_info_as_array)

        print("Length of my info {}, Lenght of QUIC info {}".format(len(own_info), len(quic_info_as_array)))
        print("Lengths are equal? {}".format(len(own_info) == len(quic_info_as_array)))

        equal = True
        for own_idx, own_char in enumerate(own_info):
            for quic_idx, quic_char in enumerate(quic_info_as_array):
                if own_idx == quic_idx:
                    if not str(own_char) == quic_char:
                        print("At my array at place {} at I have {} but QUIC has {} at place {}".format(own_idx, own_char, quic_char, quic_idx))
                        equal = False
                        break
        print(equal)

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
        output = [int(x) for x in output]
        return output

# ConnectionId: 1165101072024172724
# chlo: [67 72 76 79 17 0 0 0 80 65 68 0 125 2 0 0 83 78 73 0 140 2 0 0 83 84 75 0 196 2 0 0 83 78 79 0 248 2 0 0 86 69 82 0 252 2 0 0 67 67 83 0 12 3 0 0 78 79 78 67 44 3 0 0 65 69 65 68 48 3 0 0 83 67 73 68 64 3 0 0 80 68 77 68 68 3 0 0 73 67 83 76 72 3 0 0 80 85 66 83 104 3 0 0 77 73 68 83 108 3 0 0 75 69 88 83 112 3 0 0 88 76 67 84 120 3 0 0 67 70 67 87 124 3 0 0 83 70 67 87 128 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 119 119 119 46 101 120 97 109 112 108 101 46 111 114 103 64 231 78 140 229 135 66 76 101 84 19 224 106 253 103 121 142 210 200 123 137 36 153 108 244 192 199 115 95 92 25 112 210 250 124 217 209 54 2 4 70 144 47 202 232 5 68 215 189 58 41 132 201 237 60 131 172 9 134 147 109 163 147 238 166 216 163 255 123 221 131 162 91 21 26 1 207 222 74 182 147 236 84 126 2 174 129 29 176 255 131 186 10 32 229 246 125 119 186 196 170 57 170 192 24 121 172 255 0 0 0 0 1 232 129 96 146 146 26 232 126 237 128 134 162 21 130 145 90 195 36 239 36 77 112 163 83 250 144 134 197 111 11 144 86 145 55 102 170 140 130 241 91 121 241 58 152 16 82 86 65 69 83 71 239 154 187 151 82 232 184 165 239 123 142 144 156 119 151 5 88 53 48 57 30 0 0 0 179 47 164 4 204 68 176 75 36 126 52 97 95 35 48 100 116 77 229 210 229 216 114 94 101 70 125 159 24 237 49 25 100 0 0 0 67 50 53 53 122 204 251 15 189 103 64 17 0 192 0 0 0 128 0 0]
# scfg: [83 67 70 71 6 0 0 0 65 69 65 68 8 0 0 0 83 67 73 68 24 0 0 0 80 85 66 83 59 0 0 0 75 69 88 83 63 0 0 0 79 66 73 84 71 0 0 0 69 88 80 89 79 0 0 0 65 69 83 71 67 67 50 48 239 154 187 151 82 232 184 165 239 123 142 144 156 119 151 5 32 0 0 14 136 105 188 171 102 158 171 78 56 132 38 177 237 20 198 100 2 152 153 130 56 190 45 23 201 58 239 139 159 158 123 67 50 53 53 36 77 112 163 83 250 144 134 252 113 176 91 0 0 0 0]
# cert: [48 130 3 180 48 130 2 156 160 3 2 1 2 2 1 1 48 13 6 9 42 134 72 134 247 13 1 1 11 5 0 48 30 49 28 48 26 6 3 85 4 3 12 19 81 85 73 67 32 83 101 114 118 101 114 32 82 111 111 116 32 67 65 48 30 23 13 49 56 48 51 50 50 49 52 50 50 49 50 90 23 13 49 57 48 51 50 50 49 52 50 50 49 50 90 48 100 49 11 48 9 6 3 85 4 6 19 2 85 83 49 19 48 17 6 3 85 4 8 12 10 67 97 108 105 102 111 114 110 105 97 49 22 48 20 6 3 85 4 7 12 13 77 111 117 110 116 97 105 110 32 86 105 101 119 49 20 48 18 6 3 85 4 10 12 11 81 85 73 67 32 83 101 114 118 101 114 49 18 48 16 6 3 85 4 3 12 9 49 50 55 46 48 46 48 46 49 48 130 1 34 48 13 6 9 42 134 72 134 247 13 1 1 1 5 0 3 130 1 15 0 48 130 1 10 2 130 1 1 0 199 54 181 157 170 57 70 133 106 212 196 53 96 8 114 204 27 218 157 8 13 144 61 38 201 205 204 100 12 234 195 208 20 157 243 222 113 100 214 58 230 204 10 206 254 71 137 39 166 24 248 1 187 52 145 144 79 27 221 170 17 126 4 136 158 213 105 196 249 27 37 255 234 81 158 68 213 45 213 173 194 227 200 34 25 198 153 32 205 171 172 150 20 181 224 80 34 77 75 221 118 168 165 223 163 141 237 132 227 187 59 228 64 137 31 68 249 232 178 238 214 80 138 102 213 178 87 193 103 9 131 47 120 210 51 113 195 186 202 29 119 251 201 179 34 107 226 6 75 103 178 0 253 181 221 196 153 149 177 58 58 232 137 129 46 215 132 32 58 93 17 215 47 218 187 234 66 217 166 88 246 237 119 153 237 17 77 216 51 25 111 241 229 45 216 145 145 240 228 98 233 87 244 208 136 164 190 88 72 165 17 190 87 18 243 107 211 72 171 95 227 12 115 66 17 43 158 167 13 169 19 155 164 168 10 140 245 249 227 128 37 85 33 162 176 139 171 93 46 139 178 98 188 246 113 253 2 3 1 0 1 163 129 182 48 129 179 48 12 6 3 85 29 19 1 1 255 4 2 48 0 48 29 6 3 85 29 14 4 22 4 20 43 2 178 34 45 158 247 9 150 51 73 109 100 202 197 155 58 255 153 247 48 31 6 3 85 29 35 4 24 48 22 128 20 37 147 52 182 96 36 42 74 62 91 27 249 91 254 211 195 224 215 12 76 48 29 6 3 85 29 37 4 22 48 20 6 8 43 6 1 5 5 7 3 1 6 8 43 6 1 5 5 7 3 2 48 68 6 3 85 29 17 4 61 48 59 130 15 119 119 119 46 101 120 97 109 112 108 101 46 111 114 103 130 16 109 97 105 108 46 101 120 97 109 112 108 101 46 111 114 103 130 16 109 97 105 108 46 101 120 97 109 112 108 101 46 99 111 109 135 4 127 0 0 1 48 13 6 9 42 134 72 134 247 13 1 1 11 5 0 3 130 1 1 0 67 108 205 212 22 239 196 237 165 7 150 246 29 1 0 24 122 202 101 238 176 79 44 216 65 145 201 45 105 184 182 226 243 24 112 1 230 40 160 69 80 93 181 118 233 120 234 227 27 98 93 81 214 40 99 161 237 120 59 34 99 149 83 182 33 60 71 110 103 251 95 234 32 82 47 215 48 46 50 18 76 4 234 245 150 103 64 213 217 225 69 238 106 91 22 248 240 197 186 10 224 222 46 223 117 161 166 83 84 127 207 207 125 93 55 109 73 239 168 121 121 253 6 217 105 102 108 68 127 102 118 219 157 74 15 145 88 228 126 184 142 61 161 63 191 58 213 121 134 61 194 150 59 237 67 120 6 236 120 236 12 63 24 7 244 15 73 132 171 192 12 226 183 71 34 101 121 223 155 58 246 110 3 241 196 185 9 91 214 36 211 142 6 65 253 31 231 40 169 144 0 247 98 39 85 23 155 11 124 172 109 226 90 78 41 59 102 53 132 51 67 3 41 79 102 85 174 164 193 129 194 160 114 131 81 91 155 135 164 173 234 202 230 121 130 235 104 31 77 165 21 116 215 79 39 188]

# dhke.generate_info()
# shared_key = dhke.generate_keys(123)
# client_nonce = b'\x48\xb7\xd4\x56\x83\x08\xda\x1a\xd8\x05\x47\x98\x33\x98\xcd\x51\x37\xdb\x8f\xb9\xb9\xec\xe5\xeb\x23\xf2\x7f\x2b\x12\xe5\x9b\xf2'
# server_nonce = b''
# salt = client_nonce + server_nonce
# print(salt)
# info = dhke.generate_info()
# shared_key = bytes(dhke.quic_go_byte_array_print_to_python_array("[48 98 49 209 211 151 21 214 216 77 142 137 101 237 5 161 50 138 178 110 70 220 231 43 204 8 101 0 131 230 170 83]"))
# salt = bytes(dhke.quic_go_byte_array_print_to_python_array("[90 195 51 166 36 77 112 163 83 250 144 134 65 219 79 211 96 227 111 205 235 21 120 31 160 188 44 96 94 207 21 178 223 9 101 126 156 153 186 95 227 244 144 174 107 143 222 2 7 107 177 184 54 110 166 77 105 227 89 179 37 154 237 176 231 88 42 107 27 13 215 100 134 45 50 74 234 245 219 117 170 219 209 108]"))
#
# dhke.perform_hkdf(salt, shared_key, info)

