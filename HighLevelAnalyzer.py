# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import zlib

def decode_32bit_value(packet):
    if len(packet) != 8:
        return 0

    value = packet[-8] << 28 | packet[-7] << 24 | packet[-6] << 20 | packet[-5] << 16 | \
            packet[-4] << 12 | packet[-3] << 8  | packet[-2] << 4  | packet[-1] | \
            packet[-8] & 0xF0
    return value


def check_crc(packet):

    if len(packet) < 10:
        return False

    received = decode_32bit_value(packet[-8:])
    crc = zlib.crc32(packet[:-8]) & 0xffffffff

    if received == crc:
        return True
    else:
        print('BAD CRC', hex(received), "should be", hex(crc))
        return False


def describe_packet(packet):
    if not check_crc(packet):
        return 'BAD CRC'
    
    if packet[0] == 0:
        description = 'CMD '
    elif packet[0] == 1:
        description = 'RSP '
    elif packet[0] == 2:
        description = 'DBG '
    else:
        return 'UNK'

    if packet[1] == 0:
        description += 'NOP '
        if len(packet) > 10:
            description += '+'
            description += str(len(packet) - 10)
    elif packet[1] == 1:
        description += 'ID'
        if packet[0] == 1 and len(packet) > 10:
            description += ': '
            for ch in packet[2:-9]:
                description += chr(ch)
    elif packet[1] == 2:
        description += 'ECHO '
        if len(packet) > 10:
            description += '+'
            description += str(len(packet) - 10)
    elif packet[1] == 3:
        description += 'BABBLE'
        if packet[0] == 0:
            if len(packet) != 18:
                description += '(invalid)'
            else:
                description += ': '
                description += str(decode_32bit_value(packet[2:10]))
        elif packet[0] == 1:
            description += ': '
            description += str(len(packet) - 10)
    elif packet[1] == 4:
        description += 'PARAMS '
        description += str(decode_32bit_value(packet[2:10]))
        description += 'baud, config: '
        description += hex(decode_32bit_value(packet[10:18]))
    elif packet[1] == 0x1f:
        description += 'EXT '
    else:
        description += 'UNK'

    return description

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    result_types = {
        'packettype': {
            'format': '{{data.packet_description}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.packet_state = None
        self.packet_start_time = None
        self.packet = bytearray()
        self.esc_state = None

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        if 'error' in frame.data:
            self.packet_state = None
            self.packet = bytearray()
            self.esc_state = None
            return None

        ch = frame.data['data']

        if self.packet_state == None:       # looking for starting flag
            if ch == b'\x10':
                self.packet_state = 1
                self.packet = bytearray()
                self.packet_start_time = frame.start_time
        else:
            if ch == b'\x10':
                if len(self.packet) >= 10:
                    self.packet_state = None
                    return AnalyzerFrame('packettype', self.packet_start_time,
                            frame.end_time, {
                                'packet_description': describe_packet(self.packet)
                            })
                else:
                    self.packet_state = 1
                    self.packet = bytearray()
                    self.packet_start_time = frame.start_time
            else:
                if ch == b'\x1b':           # FESC
                    self.esc_state = 1
                    return None
                elif self.esc_state:
                    self.esc_state = None
                    if ch == b'\x1c':        # TFESC
                        ch = b'\x10'        # transpose to FESC
                    elif ch == b'\x1d':     # TFEND
                        ch = b'\x1b'        # transpose to FEND
                    else:                   # ill-formed framing
                        self.packet_state = None
                        return None
                self.packet.extend(ch)

