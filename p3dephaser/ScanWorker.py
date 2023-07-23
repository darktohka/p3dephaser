from PySide6.QtCore import QObject, QRunnable, Signal
from .Multifile import Multifile, NotEncryptedException, UnimplementedEncryptionException
from .StructDatagram import StructDatagramException
from mem_edit import Process
import ctypes, struct, string, traceback, sys
import io, os

POINTER = '<Q'

MULTIFILE_STRUCT_SIZE = 1800 # The maximum size of the multifile struct
SIZEOF_STRING = 24 # The size of an std::string

PRINTABLE_CHARS = string.printable.encode('utf-8')[:-5]

class ScanWorkerSignals(QObject):
    finished = Signal()
    warning = Signal(str)
    progress = Signal(str, bytes)
    error = Signal(tuple)

STRING_IMPLEMENTATIONS = [
    [(16, 24), (0, 8), 16, False], # MSVC
    [(8, 16), (16, 24), 23, True]  # libc++
]

class ScanWorker(QRunnable):

    def __init__(self, base, pid, multifiles):
        QRunnable.__init__(self)
        self.base = base
        self.pid = pid
        self.multifiles = multifiles
        self.multifile_names = [os.path.basename(f) for f in self.multifiles]
        self.signals = ScanWorkerSignals()

    def find_string(self, process, value):
        buffer = (ctypes.c_ubyte * len(value))(*[ord(num) for num in value])
        return process.search_all_memory(buffer)

    def read_std_string(self, process, addr):
        str_buffer = (ctypes.c_ubyte * SIZEOF_STRING)()
        arr = process.read_memory(addr, str_buffer)

        for impl in STRING_IMPLEMENTATIONS:
            length_offset, pointer_offset, short_length, use_flag = impl
            length_a, length_b = length_offset
            pointer_a, pointer_b = pointer_offset

            if use_flag and arr[0] & 1 == 0:
                # Small string optimization using LSB flag
                short_length = arr[0] & 0xFE
                yield bytes(arr[1:short_length])
                continue

            length = struct.unpack(POINTER, bytes(arr[length_a:length_b]))[0]

            if length < short_length:
                # Small string optimization
                yield bytes(arr[0:length])
                continue

            if length > 1000:
                # Suspiciously large
                continue

            # Read for string from the heap
            buffer = (ctypes.c_ubyte * length)()
            target_addr = struct.unpack(POINTER, bytes(arr[pointer_a:pointer_b]))[0]
            yield bytes(process.read_memory(target_addr, buffer))

    def read_std_strings(self, process, addresses, offset):
        for address in addresses:
            if self.base.stop_event.is_set():
                break

            address += offset

            for value in self.read_std_string(process, address):
                yield value

    def find_passwords(self, process, addr, value, mf):
        # Step one: Peek 128 bytes behind the string and 128 bytes ahead in memory
        length = len(value)
        buffer_size = 256 + length
        buffer = (ctypes.c_ubyte * buffer_size)()
        arr = bytes(process.read_memory(addr - 128, buffer))

        # Step two: Interpolate string until non-ASCII character found
        try:
            index = arr.index(value.encode('utf-8'))
        except:
            return

        start_addr = None

        for i in range(index, 0, -1):
            if arr[i] not in PRINTABLE_CHARS:
                start_addr = i + 1
                break

        # Invalid string
        if start_addr is None:
            return

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
                return

        yield target

        for offset in range(-MULTIFILE_STRUCT_SIZE, MULTIFILE_STRUCT_SIZE):
            if self.base.stop_event.is_set():
                break

            for password in self.read_std_strings(process, filename_occurrences, offset):
                if mf.is_password(password):
                    yield password

    def search_memory(self):
        with Process.open_process(self.pid) as process:
            for i, multifile_name in enumerate(self.multifile_names):
                if self.base.stop_event.is_set():
                    return

                mf = Multifile()

                with io.open(self.multifiles[i], 'rb', buffering=4096) as f:
                    try:
                        mf.load(f)
                    except NotEncryptedException:
                        self.signals.warning.emit(f'{multifile_name} is not an encrypted multifile.')
                        continue
                    except UnimplementedEncryptionException:
                        self.signals.warning.emit(f'{multifile_name} contains an encryption algorithm that has not been implemented.')
                        continue
                    except StructDatagramException:
                        self.signals.warning.emit(f'{multifile_name} is a malformed multifile.')
                        continue

                multifiles = self.find_string(process, multifile_name)

                if not multifiles:
                    continue

                for multifile in multifiles:
                    if self.base.stop_event.is_set():
                        return

                    passwords = self.find_passwords(process, multifile, multifile_name, mf)

                    try:
                        target = next(passwords)
                    except StopIteration:
                        # No passwords found
                        continue

                    target = target.decode('utf-8', 'backslashreplace')
                    target = target.replace('\\', '/')

                    for password in passwords:
                        if self.base.stop_event.is_set():
                            return

                        self.signals.progress.emit(target, password)

    def run(self):
        try:
            self.search_memory()
        except:
            traceback.print_exc()
            exc, value = sys.exc_info()[:2]
            self.signals.error.emit((exc, value, traceback.format_exc()))
        finally:
            self.signals.finished.emit()
