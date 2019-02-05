import struct
import binascii

CODE_SIZE = 2
LENGTH_SIZE = 2
HEADER_SIZE = CODE_SIZE + LENGTH_SIZE

EMPTY_LENGTH = 0

CODE_MOTD = 1
CODE_MOTD_REQUEST = 2
CODE_COMMAND_SUCCESS = 10
CODE_COMMAND_ERROR = 11
CODE_REGISTER_USER = 100
CODE_USER_STATUS = 101
CODE_WHOAMI = 110 

class Message():
    """ A class representing any message in the Cluck protocol. """
    
    def __init__(self, code, data):
        self.code = code
        self.data = data
    
    def __str__(self):
        code = self.get_code()
        length = self.get_length()
        data = self.get_data()
        return 'message(code={0}, length={1}, data={2})'.format(code, length, data)
        
    def get_code(self):
        """
        Returns the message code of this message.
        
        Returns:
        code (int): a message code.
        """
        return self.code
    
    def get_length(self):
        """
        Returns the length of the message data.
        
        Returns:
        length (int): the length of the message data.
        """
        if self.data:
            return len(self.data)
        else:
            return EMPTY_LENGTH
    
    def get_data(self):
        """
        Returns the message data.
        
        Returns:
        data (bytes): the message data. Can be None if not present.
        """
        return self.data
    
    def get_data_ascii(self):
        """
        Returns an ASCII representation of the message data.
        This method can fail if the message data does not decode
        to ASCII.
        
        Returns:
        data (string): the message data in ASCII format.
        """
        return self.data.decode()
    
    def has_data(self):
        """
        Does this message have data?
        
        Returns:
        true or false
        """
        if self.data:
            return True
        else:
            return False
    
    def pack(self):
        return self._pack_header() + self.data

    def _pack_header(self):
        return self._pack_code() + self._pack_length()
    
    def _pack_code(self):
        return struct.pack('!H', self.code)
    
    def _pack_length(self):
        return struct.pack('!H', self.get_length())

def decode(raw):
    code = unpack_code(raw)
    length = unpack_length(raw)
    data = unpack_data(raw, length)
    return Message(code, data)
    
def unpack_code(raw):
    return struct.unpack('!H', raw[0:CODE_SIZE])[0]
    
def unpack_length(raw):
    return struct.unpack('!H', raw[CODE_SIZE:CODE_SIZE + LENGTH_SIZE])[0]

def unpack_data(raw, length):
    if length > 0 and length < len(raw):
        return raw[HEADER_SIZE:HEADER_SIZE + length]
    else:
        return None

# Utility methods for creating messages.
def pack_motd(text):
    return Message(CODE_MOTD, text.encode()).pack()

def pack_motd_req():
    return Message(CODE_MOTD_REQUEST, None).pack()

def pack_cmd_success(text):
    return Message(CODE_COMMAND_SUCCESS, text.encode()).pack()

def pack_cmd_error(text):
    return Message(CODE_COMMAND_ERROR, text.encode()).pack()

def pack_register_user(text):
    return Message(CODE_REGISTER_USER, text.encode()).pack()

def pack_user_status(text):
    return Message(CODE_USER_STATUS, text.encode()).pack()

def pack_whoami():
    return Message(CODE_WHOAMI, None).pack()
