import asyncio
import cluck_message
import re
import sqlite3
import sys
import logging
import struct
import traceback
from datetime import datetime
from passlib.hash import bcrypt_sha256
from pyfiglet import Figlet

DEBUG = True

LINE_SEPARATOR = '-----------------------------'

STATE_CONNECTED = 'connecting'
STATE_READY = 'ready'
STATE_ERROR = 'error'

def main():
    if DEBUG:
        logging.basicConfig(level=logging.DEBUG)
        
    if len(sys.argv) != 3:
        print("usage: python3 server.py <host_address> <host_port>")
    else:
        host_address = sys.argv[1]
        host_port = sys.argv[2]
        run_server(host_address, host_port)

def run_server(host_address, host_port):
        connections = []
        connection_states = {}

        loop = asyncio.get_event_loop()
        coro = loop.create_server(
            lambda: CluckServer(connections, connection_states), host_address, host_port)
        server = loop.run_until_complete(coro)
        
        logging.info('main: serving on {}'.format(server.sockets[0].getsockname()))
        
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logging.info('main: server shutting down')
        finally:
            server.close()
            loop.run_until_complete(server.wait_closed())
            loop.close()

class CluckServer(asyncio.Protocol):
    def __init__(self, connections, connection_states):
        self.user = None
        self.connections = connections
        self.connection_states = connection_states

        self._protocol_paths = {}
        self._protocol_paths[cluck_message.CODE_MOTD_REQUEST] = self._handle_motd_request
        self._protocol_paths[cluck_message.CODE_REGISTER_USER] = self._handle_register_user
        self._protocol_paths[cluck_message.CODE_WHOAMI] = self._handle_whoami_request

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        logging.info('connection_made: {}'.format(peername))
        self._initialize_connection(transport)

    def data_received(self, data):
        peername = self.transport.get_extra_info('peername')
        logging.debug('data_received: {0} {1}'.format(peername, data))
        try:
            if len(data) < cluck_message.HEADER_SIZE:
                logging.warning('data_received: bad header {}'.format(data))
                error = 'malformed_packet_error: incomplete header, {}'.format(data)
                self._send(cluck_message.pack_cmd_error(error))
            else:
                message = cluck_message.decode(data)
                code = message.get_code()
                if code in self._protocol_paths:
                    self._protocol_paths[code](message)
                else:
                    logging.warning('data_received: bad message code {}'.format(code))
                    error = 'malformed_packet_error: bad message code ({})'.format(code)
                    self._send(cluck_message.pack_cmd_error(error))
        except Exception as e:
            logging.error('data_received: {}'.format(e))
            traceback.print_exc()

    def connection_lost(self, exc):
        peername = self.transport.get_extra_info('peername')
        logging.info('connection_lost: {}'.format(peername))
        self.transport.close()
        self.connections.remove(self.transport)
        self.connection_states.pop(self.transport)

    def get_motd(self):
        """
        Returns the default message of the day.
        
        Returns:
        motd [string]: a generic message of the day, useful for testing.
        """
        figlet = Figlet(font='slant')
        motd = figlet.renderText('Cluck!')
        return motd

    def _handle_whoami_request(self, message):
        """
        Handles whoami requests requested by this connection.
        
        Parameters:
        message (Message): a whoami message object.
        """
        user = self.user
        if user:
            self._send(cluck_message.pack_user_status(user))
        else:
            error = 'user_status: host has no registered users.'
            self._send(cluck_message.pack_cmd_error(error))

    def _handle_register_user(self, message):
        """
        Handles whoami requests requested by this connection.
        
        Parameters:
        message (Message): a register_user message object.
        """
        if message.has_data():
            user = message.get_data_ascii()
        else:
            user = ''
        error = validate_username(user)
        if error:
            logging.debug('handle_register_user: {}'.format(error))
            response = 'register_user_error: {}'.format(error)
            self._send(cluck_message.pack_cmd_error(response))
        else:
            logging.info('handle_register_user: creating user {}'.format(user))
            self.user = user
            response = 'register_user_success: {} confirmed.'.format(user)
            self._send(cluck_message.pack_cmd_success(response))

    def _handle_motd_request(self, message):
        """
        Writes the message of the day (MotD) to this connection's transport.
        
        Parameters:
        message (Message): a motd_request message object.
        """
        motd = self.get_motd()
        self._send(cluck_message.pack_motd(motd))

    def _initialize_connection(self, transport):
        """
        Initializes this connection and registers it with the server context.
        
        Parameters:
        transport [Transport]: this connection's asyncio transport object.
        """
        self.transport = transport
        self.connections.append(transport)
        self.connection_states[transport] = STATE_CONNECTED

    def _get_state(self):
        """
        Returns the connection state for this protocol.
        
        Returns:
        state (string): the state of this protocol's connection.
        """
        return self.connection_states[self.transport]

    def _set_state(self, state):
        """
        Sets the connection state for this protocol.
        
        Parameters:
        state (string): the new state of this protocol's connection.
        """
        self.connection_states[self.transport] = state
        
    def _send(self, data):
        """
        Sends data using the calling protocol's transport mechanism.
        
        Parameters:
        data (bytes): The message to send.
        """
        self._send_to(data, self.transport)
    
    def _send_to(self, data, transport):
        """
        Sends data using the provided transport mechanism.
        
        Parameters:
        data (bytes): The message to send.
        transport (Transport): An initialized, active asyncio Transport object.
        """
        transport.write(data)
    
    def _broadcast(self, data):
        """
        Broadcasts data to all connections.
        
        Parameters:
        message (string): The message to broadcast.
        """
        for transport in self.connections:
            conn_state = self.connection_states[transport]
            if conn_state == STATE_READY:
                self._send_to(data, transport)

# Utility functions.

def get_timestamp():
    """
    Returns a human-readable timestamp for the current time.
    
    Returns:
    timestamp (string): Human-readable timestamp.
    """
    return '{:%H:%M:%S}'.format(datetime.now())

# Validation functions.

def validate_username(username):
    """
    Validates the input username against several policies.
    
    Returns:
    error (string): an error indicating what was wrong with the username.
                    if None, the username is fine
    """
    if len(username) < 1:
        return 'user names must contain least one character.'
    elif len(username) > 12:
        return 'user names cannot contain more than twelve characters.'
    elif not username[0].isalpha():
        return 'user names must begin with alphanumeric characters.'
    elif re.search(r"\s", username):
        return 'user names cannot contain whitespace.'
    else:
        return None

if __name__ == "__main__":
    main()
