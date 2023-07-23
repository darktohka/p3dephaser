from .StructDatagram import StructDatagramIterator
from .Blowfish import Blowfish
from .AES import AES
import io, hashlib, hmac

# Multifile flags
SF_compressed = 0x0008
SF_encrypted = 0x0010
SF_signature = 0x0020

# Panda3D specific encryption header
MAGIC_HEADER = b'crypty'
MAGIC_HEADER_SIZE = len(MAGIC_HEADER)
ITERATION_FACTOR = 100

# OpenSSL encryption algorithms
NID_bf_cbc = 91
NID_aes_256_cbc = 427

NID_to_cipher = {
    NID_bf_cbc: Blowfish,
    NID_aes_256_cbc: AES
}
NID_to_sizes = {
    # IV size, block size
    NID_bf_cbc: (8, 8),
    NID_aes_256_cbc: (16, 16)
}

def PKCS5_PBKDF2_HMAC_SHA1(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    num_blocks = -(-dklen // 20)
    dk = b''

    for i in range(1, num_blocks + 1):
        u_block = hmac.new(password, salt + i.to_bytes(4, 'big'), hashlib.sha1).digest()

        u_prev = u_block

        for _ in range(iterations - 1):
            u_block = hmac.new(password, u_block, hashlib.sha1).digest()
            u_prev = bytes(a ^ b for a, b in zip(u_prev, u_block))

        dk += u_prev

    return dk[:dklen]

class MultifileException(Exception):
    pass

class NotEncryptedException(MultifileException):
    pass

class UnimplementedEncryptionException(MultifileException):
    pass

class Subfile(object):

    def __init__(self):
        self.address = -1
        self.length = -1
        self.flags = 0

    def load(self, f: io.BufferedReader, address: int) -> int:
        f.seek(address)
        di = StructDatagramIterator(f.read(18))

        next_address = di.get_uint32()
        
        if next_address == 0:
            return 0
        
        self.address = di.get_uint32()
        self.length = di.get_uint32()
        self.flags = di.get_uint16()

        if (self.flags & (SF_compressed | SF_encrypted)) != 0:
            self.original_length = di.get_uint32()
        else:
            self.original_length = self.length

        return next_address

    def is_compressed(self):
        return self.flags & SF_compressed != 0

    def is_encrypted(self):
        return self.flags & SF_encrypted != 0

    def is_signature(self):
        return self.flags & SF_signature != 0

    def __str__(self):
        return f'Subfile with length {self.length} flags {self.flags} at {self.address}. Compressed: {self.is_compressed()}, encrypted: {self.is_encrypted()}'

class Multifile(object):
    HEADER = b'pmf\0\n\r'

    def __init__(self):
        self.major_version = 0
        self.minor_version = 0
        self.scale_factor = 0
        self.timestamp = 0

    def load(self, f: io.BufferedReader):
        data = f.read(18)

        di = StructDatagramIterator(data)
        header = di.extract_bytes(6)

        if header != self.HEADER:
            raise MultifileException('Invalid multifile header.')

        self.major_version = di.get_int16()
        self.minor_version = di.get_int16()
        self.scale_factor = di.get_uint32()
        self.timestamp = di.get_uint32()

        next_address = di.get_current_index()
        encrypted_subfile = None

        while next_address != 0:
            subfile = Subfile()
            next_address = subfile.load(f, next_address)

            if subfile.is_encrypted() and not subfile.is_signature():
                encrypted_subfile = subfile
                break

        if not encrypted_subfile:
            raise NotEncryptedException('Multifile is not encrypted!')

        f.seek(encrypted_subfile.address)
        data = f.read(38)

        di = StructDatagramIterator(data)
        self.nid = di.get_uint16()
        self.key_length = di.get_uint16()
        self.iteration_count = (di.get_uint16() * ITERATION_FACTOR) + 1

        if self.nid not in NID_to_sizes:
            raise UnimplementedEncryptionException(f'Unimplemented encryption algorithm: {self.nid}')
        
        iv_size, block_size = NID_to_sizes[self.nid]
        self.iv = di.extract_bytes(iv_size)
        self.data = di.extract_bytes(block_size)

        self.invalid_passwords = []

    def is_password(self, password: bytes):
        if not password:
            return False

        if password in self.invalid_passwords:
            return False

        key = PKCS5_PBKDF2_HMAC_SHA1(password, self.iv, self.iteration_count, self.key_length)

        cipher = NID_to_cipher.get(self.nid)
        
        if not cipher:
            raise UnimplementedEncryptionException(f'Unimplemented encryption algorithm: {self.nid}')

        block = next(cipher(key).decrypt_cbc(self.data, self.iv))
        result = block[:MAGIC_HEADER_SIZE] == MAGIC_HEADER

        if not result:
            self.invalid_passwords.append(password)

        return result

    def __str__(self):
        return f'Panda3D Multifile version {self.major_version}.{self.minor_version} with scale factor {self.scale_factor} and timestamp {self.timestamp}'.format(
            self.major_version, self.minor_version,
            self.scale_factor,
            self.timestamp
        )
