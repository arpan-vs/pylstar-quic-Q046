

class FNV64A:

    @staticmethod
    def generate_hash(cert):
        _hash = 14695981039346656037
        # print(type(hash))
        for i in range(0,len(cert)):
            # print(int(oct(int(cert[i],16)),8))
            _hash ^= int(cert[i]) 
            _hash = (_hash * 0x100000001b3) % 2**64
            # hash = hash % 0xFFFFFFFFFFFFFFFF
        # print(_hash.to_bytes(8, byteorder="little").hex())
        return _hash.to_bytes(8, byteorder="little").hex()

# cert_localhost = "3082053b30820423a003020102021203c74ab6a5aca01f047bd53e46c47914f151300d06092a864886f70d01010b05003032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d3233313230393035303532355a170d3234303330383035303532345a301e311c301a06035504030c132a2e6c6974657370656564746563682e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100ba5e653b40e6daa06e2648d20c112a3d2487c26e4313115319adb778501f8faa4004d87ed535f14eb4bfe4c239abba66e4d2d5fed71001e253f7282f5c97498cd8ddc01ffb82ec7d0ee9159e6199d3311c0e5118e777793ca44ee8f1448b810ebd8b3e51690d99bea9a8527064c1de0fe907c5ea0f4fbc5c3fee3a629331a479db865dd6902bb39a938b20a61233a2e8bf4493634ba1c7ae1e304c998c136fcab0f550f430190b048f4c21c524105ba7a1e1d83715ab5522ab520a64b1bf379ac9912f00f907ca11ff90660dbad1f45063eb3d34c68cd57c66ecf6bc872af79031fb2ac12fa54c1037d796c13f627dc2fce2281a9989c995992ed1fe3f2f6fcd0203010001a382025d30820259300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e0416041459b15e8b370af753815b1dc7d5647ee5d4204564301f0603551d23041830168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f72332e692e6c656e63722e6f72672f30660603551d11045f305d82172a2e6170692e6c6974657370656564746563682e636f6d82132a2e6c6974657370656564746563682e636f6d821a2a2e77702e6170692e6c6974657370656564746563682e636f6d82116c6974657370656564746563682e636f6d30130603551d20040c300a3008060667810c01020130820104060a2b06010401d6790204020481f50481f200f000760076ff883f0ab6fb9551c261ccf587ba34b4a4cdbb29dc68420a9fe6674c5a3a740000018c4d2e3fec00000403004730450221009f1bb83f3a7936f22344eed1fd57c15390b38bf1c873c5d5ee557b7d4890e9a202207c8a285e9e4cfca70f33e879a8d31686c378cb534f9c995751a17bd9445914ef00760048b0e36bdaa647340fe56a02fa9d30eb1c5201cb56dd2c81d9bbbfab39d884730000018c4d2e3f950000040300473045022002b1d9f0cf575c8f3e95a8cb955b7320b124cb8cf2346a1656ce20d52f09e6ed022100f818cf71ceb4dcbb66879bb699ff2019336349fc8f808fedb0c8ad8a1c6f6be5300d06092a864886f70d01010b050003820101002aa655531300eb4b67e5e11d02e39382c34f0d5045d8478788dade1ba6cbab959d826b87bedd4b808eaee808e59e234835cc6cc233c2960b09729f2b6b45f0b2d6bebcb65866afd81226edcb0906fa54ec408b1036a6676dce361f5c3022fabd9a239cd24efe6582ccb181492d7f607b23f190ff4967040c69051714f159c2db38f797bb1ca2be125b1b5d65c331b2fe9b4724bd253bfb57306604aaf900fb48da21e08e92e9c0f38a499372cde8266c780366a20c6e224a352d17156383f4f8bd9ed3f63e5809366fbec5ed5a8379c316f9f9aacb39cad1c35c82474d400832e1b401f1dc9433331ef764d43e35aeb24f2526d0afa4b002c062b389b1862c97" # for localhost
# print(cert_localhost)
# FNV64A.generate_hash(bytes.fromhex(cert_localhost))