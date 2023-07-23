import struct

class StructDatagramException(Exception):
    pass

class StructDatagram(object):

    def __init__(self, data=None, stdfloat_double=False):
        self.data = data or b''
        self.stdfloat_double = stdfloat_double

    def get_message(self):
        return self.data

    def get_length(self):
        return len(self.data)

    def clear(self):
        self.data = b''

    def set_stdfloat_double(self, stdfloat_double):
        self.stdfloat_double = stdfloat_double

    def get_stdfloat_double(self):
        return self.stdfloat_double

    def pack_value(self, value_format, value):
        self.data += struct.pack(value_format, value)

    def add_bool(self, value):
        return self.pack_value('<B', bool(value))

    def add_int8(self, value):
        return self.pack_value('<b', value)

    def add_int16(self, value):
        return self.pack_value('<h', value)

    def add_int32(self, value):
        return self.pack_value('<i', value)

    def add_int64(self, value):
        return self.pack_value('<q', value)

    def add_uint8(self, value):
        return self.pack_value('<B', value)

    def add_uint16(self, value):
        return self.pack_value('<H', value)

    def add_uint32(self, value):
        return self.pack_value('<I', value)

    def add_uint64(self, value):
        return self.pack_value('<Q', value)

    def add_float32(self, value):
        return self.pack_value('<f', value)

    def add_float64(self, value):
        return self.pack_value('<d', value)

    def add_stdfloat(self, value):
        if self.stdfloat_double:
            return self.add_float64(value)

        return self.add_float32(value)

    def add_be_int16(self, value):
        return self.pack_value('>h', value)

    def add_be_int32(self, value):
        return self.pack_value('>i', value)

    def add_be_int64(self, value):
        return self.pack_value('>q', value)

    def add_be_uint16(self, value):
        return self.pack_value('>H', value)

    def add_be_uint32(self, value):
        return self.pack_value('>I', value)

    def add_be_uint64(self, value):
        return self.pack_value('>Q', value)

    def add_be_float32(self, value):
        return self.pack_value('>f', value)

    def add_be_float64(self, value):
        return self.pack_value('>d', value)

    def add_string(self, value):
        if len(value) > 65535:
            raise StructDatagramException(f'Can not pack this length to a 16-bit string: {len(value)}')

        self.add_uint16(len(value))
        return self.append_data(value)

    def add_string32(self, value):
        if len(value) > 4294967295:
            raise StructDatagramException(f'Can not pack this length to a 32-bit string: {len(value)}')

        self.add_uint32(len(value))
        return self.append_data(value)

    def add_z_string(self, value):
        self.append_data(value)
        return self.add_uint8(0)

    def add_fixed_string(self, value, size):
        length = len(value)

        if length < size:
            self.append_data(value)
            return self.pad_bytes(size - length)

        return self.append_data(value[:size])

    def add_wstring(self, value):
        return self.add_string32(value)

    def add_blob(self, value):
        if len(value) > 65535:
            raise StructDatagramException(f'Can not pack this length to a 16-bit blob: {len(value)}')

        self.add_uint16(len(value))
        return self.append_data(value)

    def add_blob32(self, value):
        if len(value) > 4294967295:
            raise StructDatagramException(f'Can not pack this length to a 32-bit blob: {len(value)}')

        self.add_uint32(len(value))
        return self.append_data(value)

    def pad_bytes(self, size):
        self.data += b'\x00' * size

    def append_data(self, data):
        if not isinstance(data, bytes):
            data = str(data)
            data = data.encode('utf-8')

        self.data += data

    def __bytes__(self):
        return self.data

    get_data = get_message

    getData = get_data
    getMessage = get_message
    getLength = get_length

    setStdfloatDouble = set_stdfloat_double
    getStdfloatDouble = get_stdfloat_double

    packValue = pack_value

    addBool = add_bool

    addInt8 = add_int8
    addInt16 = add_int16
    addInt32 = add_int32
    addInt64 = add_int64
    addUint8 = add_uint8
    addUint16 = add_uint16
    addUint32 = add_uint32
    addUint64 = add_uint64

    addFloat32 = add_float32
    addFloat64 = add_float64
    addStdfloat = add_stdfloat

    addBeInt16 = add_be_int16
    addBeInt32 = add_be_int32
    addBeInt64 = add_be_int64
    addBeUint16 = add_be_uint16
    addBeUint32 = add_be_uint32
    addBeUint64 = add_be_uint64
    addBeFloat32 = add_be_float32
    addBeFloat64 = add_be_float64

    addString = add_string
    addString32 = add_string32
    addZstring = add_z_string
    addFixedString = add_fixed_string
    addWstring = add_wstring

    addBlob = add_blob
    addBlob32 = add_blob32

    padBytes = pad_bytes
    appendData = append_data

class StructDatagramIterator(object):

    def __init__(self, datagram=None, offset=0):
        if datagram:
            if isinstance(datagram, StructDatagram):
                self.data = datagram.data[offset:]
                self.stdfloat_double = datagram.stdfloat_double
            elif isinstance(datagram, bytes):
                self.data = datagram
                self.stdfloat_double = False
            else:
                raise StructDatagramException('Invalid source datagram given.')
        else:
            self.data = b''
            self.stdfloat_double = False

        self.index = 0

    def get_remaining_size(self):
        return len(self.data) - self.index

    def get_remaining_bytes(self):
        return self.data[self.index:]

    def get_datagram(self):
        return StructDatagram(self.data, self.stdfloat_double)

    def get_current_index(self):
        return self.index

    def skip_bytes(self, size):
        remaining_size = self.get_remaining_size()

        if remaining_size < size:
            raise StructDatagramException(f'Datagram overflow: Attempted to skip {size} bytes, remaining size {remaining_size}, index {self.index}, datagram: {self.data}')

        self.index += size

    def peek_bytes(self, size):
        remaining_size = self.get_remaining_size()

        if remaining_size < size:
            raise StructDatagramException(f'Datagram overflow: Attempted to read {size} bytes, remaining size {remaining_size}, index {self.index}, datagram: {self.data}')

        return self.data[self.index:self.index + size]

    def extract_bytes(self, size):
        value = self.peek_bytes(size)
        self.index += size
        return value

    def peek_value(self, value_format):
        size = struct.calcsize(value_format)
        return struct.unpack(value_format, self.peek_bytes(size))[0]

    def extract_value(self, value_format):
        size = struct.calcsize(value_format)
        return struct.unpack(value_format, self.extract_bytes(size))[0]

    def get_bool(self):
        return bool(self.extract_value('<B'))

    def get_int8(self):
        return self.extract_value('<b')

    def get_int16(self):
        return self.extract_value('<h')

    def get_int32(self):
        return self.extract_value('<i')

    def get_int64(self):
        return self.extract_value('<q')

    def get_uint8(self):
        return self.extract_value('<B')

    def get_uint16(self):
        return self.extract_value('<H')

    def get_uint32(self):
        return self.extract_value('<I')

    def get_uint64(self):
        return self.extract_value('<Q')

    def get_float32(self):
        return self.extract_value('<f')

    def get_float64(self):
        return self.extract_value('<d')

    def get_stdfloat(self):
        if self.stdfloat_double:
            return self.get_float64()

        return self.get_float32()

    def get_be_int16(self):
        return self.extract_value('>h')

    def get_be_int32(self):
        return self.extract_value('>i')

    def get_be_int64(self):
        return self.extract_value('>q')

    def get_be_uint16(self):
        return self.extract_value('>H')

    def get_be_uint32(self):
        return self.extract_value('>I')

    def get_be_uint64(self):
        return self.extract_value('>Q')

    def get_be_float32(self):
        return self.extract_value('>f')

    def get_be_float64(self):
        return self.extract_value('>d')

    def get_string(self):
        length = self.get_uint16()
        return self.get_fixed_string(length)

    def get_string32(self):
        length = self.get_uint32()
        return self.get_fixed_string(length)

    def get_z_string(self):
        length = 0

        try:
            while self.data[self.index + length] != 0:
                length += 1
        except IndexError:
            raise StructDatagramException(f'Zero terminated string was not terminated at index {self.index}, datagram: {self.data}')

        value = self.get_fixed_string(length)
        self.skip_bytes(1)
        return value

    def get_fixed_string(self, size):
        return self.extract_bytes(size).decode('utf-8')

    def get_wstring(self):
        return self.get_string32()

    def get_blob(self):
        length = self.get_uint16()
        return self.extract_bytes(length)

    def add_blob32(self, value):
        length = self.get_uint32()
        return self.extract_bytes(length)

    def peek_bool(self):
        return bool(self.peek_value('<B'))

    def peek_int8(self):
        return self.peek_value('<b')

    def peek_int16(self):
        return self.peek_value('<h')

    def peek_int32(self):
        return self.peek_value('<i')

    def peek_int64(self):
        return self.peek_value('<q')

    def peek_uint8(self):
        return self.peek_value('<B')

    def peek_uint16(self):
        return self.peek_value('<H')

    def peek_uint32(self):
        return self.peek_value('<I')

    def peek_uint64(self):
        return self.peek_value('<Q')

    def peek_float32(self):
        return self.peek_value('<f')

    def peek_float64(self):
        return self.peek_value('<d')

    def peek_stdfloat(self):
        if self.stdfloat_double:
            return self.peek_float64()

        return self.peek_float32()

    def peek_be_int16(self):
        return self.peek_value('>h')

    def peek_be_int32(self):
        return self.peek_value('>i')

    def peek_be_int64(self):
        return self.peek_value('>q')

    def peek_be_uint16(self):
        return self.peek_value('>H')

    def peek_be_uint32(self):
        return self.peek_value('>I')

    def peek_be_uint64(self):
        return self.peek_value('>Q')

    def peek_be_float32(self):
        return self.peek_value('>f')

    def peek_be_float64(self):
        return self.peek_value('>d')

    def peek_string(self):
        length = self.peek_uint16()
        return self.peek_bytes(2 + length).decode('utf-8')[2:]

    def peek_string32(self):
        length = self.peek_uint32()
        return self.peek_bytes(4 + length).decode('utf-8')[4:]

    def peek_z_string(self):
        length = 0

        try:
            while self.data[self.index + length] != 0:
                length += 1
        except IndexError:
            raise StructDatagramException(f'Zero terminated string was not terminated at index {self.index}, datagram: {self.data}')

        return self.peek_fixed_string(length)

    def peek_fixed_string(self, size):
        return self.peek_bytes(size).decode('utf-8')

    def peek_wstring(self):
        return self.peek_string32()

    def peek_blob(self):
        length = self.peek_uint16()
        return self.peek_bytes(2 + length)[2:]

    def peek_blob32(self, value):
        length = self.peek_uint32()
        return self.peek_bytes(4 + length)[4:]

    getRemainingSize = get_remaining_size
    getRemainingBytes = get_remaining_bytes
    getDatagram = get_datagram
    getCurrentIndex = get_current_index

    skipBytes = skip_bytes
    peekBytes = peek_bytes
    extractBytes = extract_bytes

    peekValue = peek_value
    extractValue = extract_value

    getBool = get_bool

    getInt8 = get_int8
    getInt16 = get_int16
    getInt32 = get_int32
    getInt64 = get_int64
    getUint8 = get_uint8
    getUint16 = get_uint16
    getUint32 = get_uint32
    getUint64 = get_uint64

    getFloat32 = get_float32
    getFloat64 = get_float64
    getStdfloat = get_stdfloat

    getBeInt16 = get_be_int16
    getBeInt32 = get_be_int32
    getBeInt64 = get_be_int64
    getBeUint16 = get_be_uint16
    getBeUint32 = get_be_uint32
    getBeUint64 = get_be_uint64
    getBeFloat32 = get_be_float32
    getBeFloat64 = get_be_float64

    getString = get_string
    getString32 = get_string32
    getZstring = get_z_string
    getFixedString = get_fixed_string
    getWstring = get_wstring

    getBlob = get_blob
    getBlob32 = add_blob32

    peekBool = peek_bool

    peekInt8 = peek_int8
    peekInt16 = peek_int16
    peekInt32 = peek_int32
    peekInt64 = peek_int64
    peekUint8 = peek_uint8
    peekUint16 = peek_uint16
    peekUint32 = peek_uint32
    peekUint64 = peek_uint64

    peekFloat32 = peek_float32
    peekFloat64 = peek_float64
    peekStdfloat = peek_stdfloat

    peekBeInt16 = peek_be_int16
    peekBeInt32 = peek_be_int32
    peekBeInt64 = peek_be_int64
    peekBeUint16 = peek_be_uint16
    peekBeUint32 = peek_be_uint32
    peekBeUint64 = peek_be_uint64
    peekBeFloat32 = peek_be_float32
    peekBeFloat64 = peek_be_float64

    peekString = peek_string
    peekString32 = peek_string32
    peekZstring = peek_z_string
    peekFixedString = peek_fixed_string
    peekWstring = peek_wstring

    peekBlob = peek_blob
    peekBlob32 = add_blob32
