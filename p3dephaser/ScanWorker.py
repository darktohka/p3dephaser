from PySide6.QtCore import QObject, QRunnable, Signal
from mem_edit import Process
import ctypes, struct, string, traceback, sys

POINTER = '<Q'
POINTER_SIZE = 8
FILENAME_OFFSET = -1216 # Between filename and password
TIMESTAMP_OFFSET = 40 # Between timestamp and password
VERSION_OFFSET = 1336 # Between password and version

PRINTABLE_CHARS = string.printable.encode('utf-8')[:-5]

class ScanWorkerSignals(QObject):
    finished = Signal()
    progress = Signal(str, str)
    error = Signal(tuple)

class ScanWorker(QRunnable):

    def __init__(self, base, pid, multifiles):
        QRunnable.__init__(self)
        self.base = base
        self.pid = pid
        self.multifiles = multifiles
        self.signals = ScanWorkerSignals()

    def find_string(self, process, value):
        buffer = (ctypes.c_ubyte * len(value))(*[ord(num) for num in value])
        return process.search_all_memory(buffer)

    def read_std_string(self, process, addr):
        boundary = 16 + POINTER_SIZE
        str_buffer = (ctypes.c_ubyte * boundary)()
        arr = process.read_memory(addr, str_buffer)
        length = struct.unpack(POINTER, bytes(arr[16:boundary]))[0]

        if length > 25000:
            # This is suspiciously high
            return None

        if length < 16:
            # Small string optimization
            return bytes(arr[0:length])

        # Read for string from the heap
        buffer = (ctypes.c_ubyte * length)()
        target_addr = struct.unpack(POINTER, bytes(arr[0:POINTER_SIZE]))[0]
        return bytes(process.read_memory(target_addr, buffer))

    def is_multifile(self, process, address, offset):
        # If we can find the multifile version 1.1 in the memory,
        # then we most likely have stumbled upon a multifile entry.
        mf_version = struct.pack('II', 1, 1)
        buffer = (ctypes.c_ubyte * len(mf_version))()
        version = bytes(process.read_memory(address + offset, buffer))

        return version == mf_version

    def read_std_strings(self, process, addresses, offset):
        values = []

        for address in addresses:
            if self.base.stop_event.is_set():
                continue

            address += offset

            if not self.is_multifile(process, address, VERSION_OFFSET):
                continue

            value = self.read_std_string(process, address)

            if value:
                values.append(value)

        return values

    def find_passwords(self, process, addr, value):
        # Step one: Peek 128 bytes behind the string and 128 bytes ahead in memory
        length = len(value)
        buffer_size = 256 + length
        buffer = (ctypes.c_ubyte * buffer_size)()
        arr = bytes(process.read_memory(addr - 128, buffer))

        # Step two: Interpolate string until non-ASCII character found
        index = arr.index(value.encode('utf-8'))
        start_addr = None

        for i in range(index, 0, -1):
            if arr[i] not in PRINTABLE_CHARS:
                start_addr = i + 1
                break

        # Invalid string
        if start_addr is None:
            return None, []

        value_addr = addr - 128 + start_addr
        end_addr = value_addr + length

        for i in range(index + length, buffer_size):
            if arr[i] not in PRINTABLE_CHARS:
                end_addr = i
                break

        # Our full filename begins at value_addr
        target = arr[start_addr:end_addr]

        if len(target) < 16:
            # Small string optimization
            filename_occurrences = [value_addr]
        else:
            # Search for string in the heap
            filename_occurrences = process.search_all_memory(ctypes.c_ulong(value_addr))

            if not filename_occurrences:
                # There are no occurrences
                return target, []

        passwords = self.read_std_strings(process, filename_occurrences, FILENAME_OFFSET)
        return target, passwords

    def find_passwords_from_timestamp(self, process, timestamp):
        # Find multifiles by timestamps easily
        occurrences = process.search_all_memory(ctypes.c_uint64(timestamp))
        return self.read_std_strings(process, occurrences, TIMESTAMP_OFFSET)

    def search_memory(self):
        with Process.open_process(self.pid) as process:
            for multifile_name in self.multifiles:
                if self.base.stop_event.is_set():
                    return

                multifiles = self.find_string(process, multifile_name)

                for multifile in multifiles:
                    if self.base.stop_event.is_set():
                        return

                    target, passwords = self.find_passwords(process, multifile, multifile_name)
                    target = target.decode('utf-8', 'backslashreplace')

                    for password in passwords:
                        if self.base.stop_event.is_set():
                            return

                        self.signals.progress.emit(target, password.decode('utf-8', 'backslashreplace'))

    def run(self):
        try:
            self.search_memory()
        except:
            traceback.print_exc()
            exc, value = sys.exc_info()[:2]
            self.signals.error.emit((exc, value, traceback.format_exc()))
        finally:
            self.signals.finished.emit()
