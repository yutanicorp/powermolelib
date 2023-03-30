#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: agent.py
#
# Copyright 2021 Vincent Schouten
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for Agent.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import socket
import os
import logging.config
# import coloredlogs
import threading
import http.server
import socketserver
import json
import subprocess
import select
import sys
import atexit
import signal
# from dataclasses import dataclass
from abc import ABC
from struct import pack, unpack
from os.path import basename
from time import sleep

# Constants
PORT_AGENT = 44191  # the local port the agent uses to listen for instructions from Instructor.
# IMPORTANT NOTE: other ports are sent via an Instructor class which receives it from the CLI.

# Configuration for SOCKS proxy server classes
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
VER = b'\x05'  # PROTOCOL VERSION 5
M_NOAUTH = b'\x00'  # '00' NO AUTHENTICATION REQUIRE
M_NOTAVAILABLE = b'\xff'  # 'FF' NO ACCEPTABLE METHODS
CMD_CONNECT = b'\x01'  # CONNECT '01'
ATYP_IPV4 = b'\x01'  # IP V4 address '01'
ATYP_DOMAINNAME = b'\x03'  # DOMAINNAME '03'

# Logging
LOGGER = logging.getLogger()  # not used?
LOGGER_BASENAME = '''Agent'''


class LoggerMixin:
    """Contains a logger method for use by other classes."""

    def __init__(self):
        """Initializes the LoggerMixin object."""
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')


class TransferError(Exception):
    """Something went wrong during transfer of the file."""


def validate_transfer_server_response(response):
    """Validates the data structure of the content of an incoming HTTP request.

    These requests are received by the CommandServer and contains Linux commands.
    """
    if all([isinstance(response.get('process'), str),
            isinstance(response.get('status_code'), int)]):
        return response.get('process'), response.get('status_code')
    raise InvalidDataStructure


def validate_http_instruction(request):
    """Validates the data structure of the content of an incoming HTTP request.

    These requests are received by the Agent.
    """
    process = ['transfer_server_start', 'file_server_stop', 'proxy_server_start', 'proxy_server_stop',
               'heartbeat_responder_start', 'heartbeat_responder_stop', 'command_server_start', 'command_server_stop',
               'stop']  # 'authenticate_host'
    if not all([request.get('process') in process,
                isinstance(request.get('arguments'), dict)]):
        raise InvalidDataStructure
    return request.get('process'), request.get('arguments', {})


def validate_http_command(request):
    """Validates the data structure of the content of an incoming HTTP request.

    These requests are received by the CommandServer and contains Linux commands.
    """
    if isinstance(request.get('command'), str):
        return request
    raise InvalidDataStructure


class InvalidDataStructure(Exception):
    """The data structure is invalid."""

    def __init__(self):
        super().__init__("the data structure is invalid.")


class Agent(LoggerMixin):
    """Listens for instructions send by *Instructor."""

    def __init__(self, port):
        """Initializes the Agent object.

        Args:
            port (basestring): The local port used to listen for instructions from *Instructor.

        """
        super().__init__()
        self.port = port
        self.httpd = None
        self.terminate = False
        self.transfer_server = None
        self.command_server = None
        self.heartbeat_responder = None
        self.proxy_server = None
        self.authenticate = None

    def __str__(self):
        return 'Agent'

    def start(self):
        """Listens for incoming HTTP POST request."""
        self._logger.debug('starting agent')
        threading.Thread(target=self._watcher).start()
        agent = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            """Parses HTTP requests."""

            logger_name = f'{LOGGER_BASENAME}.Handler'
            _logger = logging.getLogger(logger_name)
            socketserver.TCPServer.allow_reuse_address = True

            def do_POST(self):  # noqa
                """Creates the response."""
                try:
                    data = self.rfile.read(int(self.headers['Content-Length']))  # b'{"process":"heartbeat_responder"}
                    self._logger.debug('the following request was received from *Instructor: %s', data)
                    instruction_string = data.decode('utf-8')  # convert byte to string (to original JSON document)
                    instruction_dict = json.loads(instruction_string)  # convert JSON to dict
                    # example: {'process': 'transfer_server_start', 'arguments': {'port': 44194}}
                    # validate structure of content of req:
                    process, arguments = validate_http_instruction(instruction_dict)
                except json.decoder.JSONDecodeError:  # json.loads()
                    self._logger.error('the content is incorrectly parsed in JSON')
                    process = 'default'  # to enter exit branch
                    arguments = {}
                except InvalidDataStructure:  # validate_http_instruction()
                    self._logger.error('data structure (dict) validation failed')
                    process = 'default'  # to enter exit branch
                    arguments = {}

                if getattr(agent, f'{process}')(**arguments):  # getattr(agent, transfer_server_start(port:44194))
                    self.send_response(200)
                    self.end_headers()
                    json_instruction = json.dumps({'result': True})
                    data = json_instruction.encode('utf-8')  # from string to byte
                    self.wfile.write(data)
                else:
                    self.send_response(200)
                    self.end_headers()
                    json_instruction = json.dumps({'result': False})
                    data = json_instruction.encode('utf-8')  # from string to byte
                    self.wfile.write(data)

        with socketserver.TCPServer(("localhost", self.port), Handler) as agent.httpd:
            self._logger.debug('serving at port %s', self.port)
            agent.httpd.serve_forever()

    def _watcher(self):
        while not self.terminate:
            sleep(1)
        self._logger.debug('sending shutdown()')
        self.httpd.shutdown()

    def heartbeat_responder_start(self, **kwargs):
        """Starts the heartbeat responder."""
        port = kwargs.get('port')
        self.heartbeat_responder = HeartbeatResponder(port)
        return self.heartbeat_responder.start()

    def transfer_server_start(self, **kwargs):
        """Starts the transfer server."""
        mode = kwargs.get('mode')
        port = kwargs.get('port')
        self.transfer_server = TransferServer(port)
        return self.transfer_server.start(mode)

    def command_server_start(self, **kwargs):
        """Starts the command server."""
        port = kwargs.get('port')
        self.command_server = CommandServer(port)
        return self.command_server.start()

    def proxy_server_start(self, **kwargs):
        """Starts the proxy server."""
        i_addr = kwargs.get('inbound_address')
        i_port = kwargs.get('inbound_port')
        o_addr = kwargs.get('outbound_address')
        self.proxy_server = ProxyServer(inbound_address=i_addr,
                                        inbound_port=i_port,
                                        outbound_address=o_addr)
        return self.proxy_server.start()

    def heartbeat_responder_stop(self):
        """Stops the heartbeat responder."""
        return True if self.heartbeat_responder is None else self.heartbeat_responder.stop()

    def transfer_server_stop(self):
        """Stops the transfer server."""
        return True if self.transfer_server is None else self.transfer_server.stop()

    def command_server_stop(self):
        """Stops the command server."""
        return True if self.command_server is None else self.command_server.stop()

    def proxy_server_stop(self):
        """Stops the proxy server."""
        return True if self.proxy_server is None else self.proxy_server.stop()

    def stop(self):
        """Stops the Agent."""
        self._logger.debug('stopping heartbeat responder, and transfer, command and proxy server, if running...')
        self.heartbeat_responder_stop()
        self.proxy_server_stop()
        self.command_server_stop()
        self.transfer_server_stop()
        self._logger.debug('finally, stopping agent...')
        self.terminate = True
        return True

    def default(self):
        """Stops the Agent."""
        self._logger.debug('the process is unknown')
        # self.stop()


class TransferServer(LoggerMixin):
    """Receives file(s) sent by *Instructor()."""

    def __init__(self, port):
        """Initializes the TransferServer object."""
        super().__init__()
        self.port = port
        self.data_protocol = None
        self.terminate = False

    def start(self, mode):  # src_file_path=None, dest_path=None
        """Starts transfer server."""
        self._logger.debug('starting transfer server')
        self.data_protocol = DataProtocol(mode, self.port)
        self.data_protocol.start()
        if mode == 'receive':
            threading.Thread(target=self._receive_file).start()
        elif mode == 'send':
            return False  # not implemented, yet.
        return True

    def stop(self):
        """Stops transfer server."""
        self._logger.debug('stopping transfer server...')
        self.terminate = True
        self.data_protocol.stop()
        return True

    def _receive_file(self):
        # result = False
        try:
            while not self.terminate:
                metadata = self.data_protocol.receive_metadata()
                self.data_protocol.receive_file(metadata)
                sleep(0.1)
        except TransferError:
            self._logger.error('something went wrong during transfer')

    def _send_file(self, src_file_path, dest_path):  # NOT IMPLEMENTED
        result = False
        try:
            result = all([self.data_protocol.send_metadata(src_file_path, dest_path),
                          self.data_protocol.send_file(src_file_path)])
        except FileNotFoundError:
            self._logger.error('file or directory does not exist')
        except TransferError:
            self._logger.error('something went wrong during transfer')
        return result


class SocketServer(LoggerMixin):
    """Manages sockets."""

    def __init__(self):
        super().__init__()
        self.terminate = False
        self.socket_ = None
        self.connections = []

    def create_socket(self):
        """Creates a new INET (IPv4), STREAMing socket (TCP).

        Sockets are interior endpoints built for sending and receiving data.

        """
        try:
            self.socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as err:
            self._logger.debug("failed to create socket: %s", err)

    def listen(self, port, host='localhost'):
        """Listens for connections made to the socket."""
        self.socket_.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # to avoid "Address already in use" error, set the SO_REUSEADDR flag.
        # this tells the kernel o reuse a local socket in TIME_WAIT state,
        # without waiting for its natural timeout to expire.
        self.socket_.bind((host, port))
        # socket.bind(address) binds the socket to address.
        self._logger.debug('serving at port %s', port)
        self.socket_.listen(2)
        # listen(backlog) specifies the number of unaccepted connections that the -
        # system will allow before refusing new connections.
        self._logger.debug('waiting for a connection...')

    def handle_connections(self):
        """Accepts connections and add them to an instance var of type called connections."""

        def _conn_handler():
            while not self.terminate:  # keep listening to new connections
                try:
                    connection, _ = self.socket_.accept()  # blocking. calling close() will raise exception
                    self._logger.debug('connection received from %s to %s',
                                       connection.getsockname(), connection.getpeername())
                    self.connections.append(connection)
                except OSError:
                    pass

        threading.Thread(target=_conn_handler).start()

    def close_socket(self):  # https://stackoverflow.com/questions/409783/socket-shutdown-vs-socket-close
        """Closes socket."""
        self.terminate = True
        self.socket_.shutdown(socket.SHUT_RDWR)
        # closes the underlying connection and sends a FIN / EOF to the peer regardless of how many processes have
        # handles to the socket. However, it does not deallocate the socket and you still need to call close afterwards
        self.socket_.close()
        # it decrements the handle count by one and if the handle count has reached zero then the socket and associated
        # connection goes through the normal close procedure (effectively sending a FIN / EOF to the peer) and the
        # socket is deallocated. The thing to pay attention to here is that if the handle count does not reach zero
        # because another process still has a handle to the socket then the connection is not closed and the socket is
        # not deallocated.

    def set_outbound_address(self, address):
        """Instructs the socket to use a particular IP address for outgoing connections.

        This is relevant for hosts that have more than one IP address.
        Either way, this method should always be called prior to making outgoing connections.
        """
        try:
            self.socket_.setsockopt(
                socket.SOL_SOCKET,  # the _level_ argument to manipulate the socket-level options
                socket.AF_INET,  # the IPv4 socket option (note: SO_BINDTODEVICE enables to bind to device, eg. "eth0")
                address.encode()  # eg. b'210.33.51.4', can be an IP address on another interface on the host
            )
        except socket.error as exc:
            self._logger.info("something went wrong when setting socket operation: %s ", exc)

    def connect_to_socket(self, address, port):
        """Connects to a remote socket at given address."""
        try:
            self.socket_.connect((address, port))  # tuple
            self._logger.debug("connection established from %s to %s",
                               self.socket_.getsockname(),
                               self.socket_.getpeername())
            return True
        except socket.error as exc:
            self._logger.info("connection could not be established to %s ", exc)
            return False


class DataProtocol(SocketServer):  # LoggerMixin is subclassed by SocketServer, but I'd like to mention it here
    """Dictates how to format, transmit and receive data.

    Encodes file metadata and sends it along with the content of the (binary) file
    or decodes file metadata and writes received data to a new file.
    """

    def __init__(self, mode, port):
        """Initializes the DataProtocol object."""
        super().__init__()
        self.mode = mode
        self.port = port

    def start(self):
        """Starts the data protocol in either receiving of sending mode."""
        if self.mode == 'receive':
            self.create_socket()
            self.listen(self.port)
            self.handle_connections()
        elif self.mode == 'send':
            self.create_socket()
            self.connect_to_socket('localhost', self.port)

    def stop(self):
        """Closes the socket."""
        self.close_socket()

    def send_metadata(self, source_file_path, destination_path, padding=16):  # NOT IMPLEMENTED
        """Encodes the metadata."""
        metadata = {'dest_path': destination_path,
                    'file_name': basename(source_file_path.replace('\\', '')),
                    'file_size': str(os.path.getsize(source_file_path.replace('\\', '')))
                    }
        self.socket_.sendall(bytes('metadata', 'utf-8'))  # string is 8 bytes
        for value in metadata.values():
            self._logger.debug('convert metadata of %s to bytes and send', value)
            length = bin(len(value))[2:].zfill(padding)  # from decimal to binary (eg. 0000000000001110)
            data = bytes(length, 'utf-8')  # turns into byte (eg. b'00000000001110')
            data += bytes(value, 'utf-8')  # turns into byte (eg. b'amsterdam.jpg')
            self.socket_.sendall(data)
        return self._check_delivery_code()

    def send_file(self, source_file_path):  # NOT IMPLEMENTED
        """Sends the content of the file."""
        self._logger.debug('convert file %s to bytes and send', basename(source_file_path.replace('\\', '')))
        self.socket_.sendall(bytes('filedata', 'utf-8'))
        with open(source_file_path.replace('\\', ''), 'rb') as file:  # type is "_io.BufferedReader"
            data = file.read()
        self.socket_.sendall(data)
        return self._check_delivery_code()

    def receive_metadata(self):
        """Decodes the metadata."""
        if not self.connections:
            return None
        connection = self.connections[-1]
        process = connection.recv(8)
        if process != b'metadata':
            return None
        metadata = {'dest_path': None,
                    'file_name': None,
                    'file_size': None
                    }
        for key, _ in metadata.items():
            try:
                length_binary = connection.recv(16)
                length_int = int(length_binary, 2)
                metadata[key] = connection.recv(length_int).decode("UTF-8")
                self._logger.debug(f'{key}: {metadata[key]} received')  # logging-fstring-interpolation
            except (IOError, Exception):
                self._send_status_code(connection, 'metadata', 1)
                raise TransferError from None
        self._send_status_code(connection, 'metadata', 0)
        return metadata  # {'dest_path': '/tmp', 'file_name': 'amsterdam.jpg', 'file_size': '98130'

    def receive_file(self, metadata):
        """Writes the received data to a file."""
        if not metadata:
            return None
        connection = self.connections.pop()
        process = connection.recv(8)
        if process != b'filedata':
            return None
        file_size = int(metadata['file_size'])
        try:
            # write code to check if given destination path actually exists on last host
            # to avoid: "No such file or directory"
            path = os.path.join(metadata['dest_path'], metadata['file_name'])
            file_to_write = open(path, 'wb')  # pylint: disable=consider-using-with
            chunk_size = 4096
            while file_size > 0:
                if file_size < chunk_size:
                    chunk_size = file_size
                    self._logger.debug('receiving last chunk of data...')
                data = connection.recv(chunk_size)
                file_to_write.write(data)
                file_size -= len(data)
            file_to_write.close()
            self._logger.debug('received all chunks of data')
        except OSError:  # raised by open() or socket()
            return self._send_status_code(connection, 'filedata', 1)
        return self._send_status_code(connection, 'filedata', 0)

    def _check_delivery_code(self):
        status_code = self.socket_.recv(41)
        status_string = status_code.decode("utf-8")  # from bytes to string (containing JSON doc)
        status_string_dict = json.loads(status_string)  # from JSON doc to dict
        process, status_code = validate_transfer_server_response(status_string_dict)
        self._logger.debug('status code from transfer server: %s: %s', process, status_code)
        result = False
        if process == 'metadata' and status_code == 0:
            self._logger.debug('metadata is transferred')
            result = True
        elif process == 'filedata' and status_code == 0:
            self._logger.debug('file is transferred')
            result = True
        else:
            self._logger.error('something went wrong during transfer')
            result = False
        return result

    def _send_status_code(self, connection, process, status_code):
        if process == 'metadata' and status_code == 0:
            self._logger.debug('metadata is received successfully')
        elif process == 'filedata' and status_code == 0:
            self._logger.debug('filedata is received successfully')
        elif process in ('filedata', 'metadata') and status_code == 1:
            self._logger.error('something went wrong during transfer')
        else:
            self._logger.debug('unknown state')
        msg = {'process': f'{process}', 'status_code': int(status_code)}
        json_instruction = json.dumps(msg)  # from dict to JSON
        data = json_instruction.encode('utf-8')  # from string to byte
        try:
            connection.sendall(data)
            return True
        except OSError:
            return False


class CommandServer(LoggerMixin):
    """Listens for Linux commands send by *Instructor() and responds with result."""

    #  determine first whether port is bind or not
    #  < code >
    #  self._logger.error('Port already bind. Probably by having executed this method twice.')

    def __init__(self, port):
        """Initializes the CommandServer object.

        Args:
            port (basestring): <>

        """
        super().__init__()
        self.port = port
        self.httpd = None
        self.terminate = False

    def start(self):
        """Listens for connections."""
        self._logger.debug('starting command server...')
        threading.Thread(target=self._watcher).start()
        threading.Thread(target=self._serve).start()
        return True

    def _serve(self):
        """Listens for incoming HTTP POST request."""
        instance = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            """Parses HTTP requests."""

            logger_name = f'{LOGGER_BASENAME}.Handler'
            _logger = logging.getLogger(logger_name)
            # socketserver.BaseRequestHandler.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            socketserver.TCPServer.allow_reuse_address = True

            def do_POST(self):  # noqa
                """Creates the response containing the result."""
                try:
                    data = self.rfile.read(int(self.headers['Content-Length']))  # b'{"command":"ls -l /"}
                    self._logger.debug('following raw Linux command was received from instructor: %s', data)
                    command_string = data.decode('utf-8')  # convert byte to string in JSON format
                    command_dict = json.loads(command_string)  # convert JSON to dict
                    command_val = validate_http_command(command_dict)  # validate the structure of the content of req.
                    command = command_val.get('command')
                    instance._logger.debug('following Linux command was received from instructor: %s', command)  # pylint: disable=protected-access
                    # eg. b'{"command": "hostname"}'
                except json.decoder.JSONDecodeError:  # json.loads()
                    self._logger.error('the content is incorrectly parsed in JSON')
                    return False
                except InvalidDataStructure:  # validate_http_instruction()
                    self._logger.error('data structure (dict) validation failed')
                    return False
                result_command = instance._issue_command(command.split())  # pylint: disable=protected-access
                self.send_response(200)
                self.end_headers()
                self.wfile.write(result_command)
                result = True
                return result

        with socketserver.TCPServer(("localhost", self.port), Handler) as instance.httpd:
            self._logger.debug('serving at port %s', self.port)
            instance.httpd.serve_forever()

    def _watcher(self):
        while True:
            if self.terminate:
                self._logger.debug('sending shutdown()')
                self.httpd.shutdown()
                break

    def _issue_command(self, command):
        result = b'ERROR: command not recognized'
        try:
            result = subprocess.check_output(command).rstrip()
            self._logger.debug('result of Linux commando is %s', result)  # eg. b'server.enterprise.com'
        except FileNotFoundError:
            self._logger.error('Linux command could not be executed')
        return result

    def stop(self):
        """Stops the command server."""
        self._logger.debug('stopping command server...')
        self.terminate = True
        return True


class HeartbeatResponder(LoggerMixin):
    """Responds to GET requests from powermolecli/gui with HTTP code 200."""

    #  determine first whether port is bind or not
    #  self._logger.error('Port already bind. Probably by having executed this method twice.')

    def __init__(self, port):
        super().__init__()
        self.port = port
        self.httpd = None
        self.terminate = False

    def start(self):
        """Executes the HTTP server that responds to GET requests (heartbeats) from powermolecli/gui."""
        self._logger.debug('starting heartbeat responder...')
        threading.Thread(target=self._watcher).start()
        threading.Thread(target=self._serve).start()
        return True

    def _serve(self):
        instance = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            """Parses HTTP requests."""

            def __init__(self, *args, **kwargs):
                # kwargs['directory'] = directory  # I had to comment out, because -->
                super().__init__(*args, **kwargs)  # --> "TypeError: __init__ got an unexpected kwarg 'directory'"

            def do_GET(self):  # noqa
                """Creates the response."""
                instance._logger.debug('GET request received')  # pylint: disable=protected-access
                self.send_response(200)
                self.end_headers()

        with socketserver.TCPServer(("localhost", self.port), Handler) as instance.httpd:
            self._logger.debug('serving at port %s', self.port)
            instance.httpd.serve_forever()

    def _watcher(self):
        while True:
            if self.terminate:
                self._logger.debug('sending shutdown()')
                self.httpd.shutdown()
                break

    def stop(self):
        """Terminates the HTTP server responsible for responding to GET request."""
        self._logger.debug('stopping heartbeat responder...')
        self.terminate = True
        return True


# Daemon in Python
# from Costas Tyfoxylos costas.tyf@gmail.com
# 2019-10-17: Refactored by myself (Vincent Schouten)

# Sources:
# [1] Based on http://web.archive.org/
#                        web/20131025230048/http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
#   The changes are:
#   1 - Uses file open context managers instead of calls to file().
#   2 - Forces stdin to /dev/null. stdout and stderr go to log files.
#   3 - Uses print instead of sys.stdout.write prior to pointing stdout to the log file.
#   4 - Omits try/excepts if they only wrap one error message w/ another.
# [2] https://stackoverflow.com/questions/33560802/pythonhow-os-fork-works
# [3] https://stackoverflow.com/questions/8777602/why-must-detach-from-tty-when-writing-a-linux-daemon


class Daemon(ABC):
    """Instantiates the daemon."""

    def __init__(self, pid_file=None, stdout=None, stderr=None):
        self.stdout = stdout or './daemon_out.log'
        self.stderr = stderr or './daemon_err.log'
        self.pid_file = pid_file or './daemon.pid'

    def _remove_pid(self):
        """Deletes the pid file."""
        os.remove(self.pid_file)

    def _daemonize(self):
        """Double forking of the process."""
        # fork 1 to spin off the child that will spawn the daemon.
        if os.fork() > 0:
            sys.exit(0)  # exit first parent
        # This is the child.

        # 1. clear the session id to clear the controlling TTY.
        # 2. set the umask so we have access to all files created by the daemon.
        os.setsid()
        os.umask(0)

        # fork 2 ensures we can't get a controlling TTY [ttd]?
        if os.fork() > 0:
            sys.exit(0)  # exit from second parent
        # This is a child that can't ever have a controlling TTY.

        # redirect standard file descriptor for *stdin* (essentially shut down stdin)
        with open('/dev/null', 'r', encoding='utf-8') as dev_null:
            os.dup2(dev_null.fileno(), sys.stdin.fileno())  # os.dup <-- duplicate file descriptor

        # redirect standard file descriptor for *stderr* to log file
        sys.stderr.flush()
        with open(self.stderr, 'a+', encoding='utf-8') as stderr:
            os.dup2(stderr.fileno(), sys.stderr.fileno())  # os.dup <-- duplicate file descriptor

        # redirect standard file descriptor for *stdout* to log file
        sys.stdout.flush()
        with open(self.stdout, 'a+', encoding='utf-8') as stdout:
            os.dup2(stdout.fileno(), sys.stdout.fileno())  # os.dup <-- duplicate file descriptor

        # registered functions are executed automatically when the interpreter session is terminated normally.
        atexit.register(self._remove_pid)

        #   py interpreter
        #    |
        #   (fork) < duplicate itself
        #    |
        #    ├─ parent < exit this process!
        #    |
        #   (setsid) < detach from the terminal (ie. no controlling TTY) to avoid certain signals
        #    |
        #   (fork) < duplicate itself
        #    |
        #    ├─ parent < exit this process!
        #    |
        #    └─ child < store the pid of this process
        #
        pid = str(os.getpid())

        # write pid to file
        with open(self.pid_file, 'w', encoding='utf-8') as pid_f:
            pid_f.write(pid)

    @property
    def pid(self):
        """Returns the pid read from the pid file."""
        try:
            with open(self.pid_file, 'r', encoding='utf-8') as pid_file:
                pid = int(pid_file.read().strip())
            return pid
        except IOError:
            return None  # added "None" to avoid inconsistent-return-statements

    def start(self, function):
        """Starts the daemon."""
        # print('Starting...')
        if self.pid:
            print((f'PID file {self.pid_file} exists. '
                   'Is the daemon already running?'))
            sys.exit(1)
        self._daemonize()
        function()

    def stop(self):
        """Stops the daemon."""
        if not self.pid:
            print((f"PID file {self.pid_file} doesn't exist. "
                   "Is the daemon not running?"))
            return
        try:
            while 1:
                os.kill(self.pid, signal.SIGTERM)
                sleep(1)
        except OSError as err:
            if 'No such process' in err.strerror and \
                    os.path.exists(self.pid_file):
                os.remove(self.pid_file)
            else:
                print(err)
                sys.exit(1)

    def restart(self, function):
        """Restarts the daemon."""
        self.stop()
        self.start(function)


# Small Socks5 Proxy Server in Python
# from https://github.com/MisterDaneel/
# 2019-10-17: Refactored as OOP by Vincent Schouten (developer of powermole)
# 2021-05-16: Heavily refactored by Vincent Schouten


class ProxyServer(LoggerMixin):
    """De-encapsulating incoming SOCKS connections from client and forward data to destination host.

    SOCKS is a generic proxy protocol for TCP/IP-based networking applications.

    Authentication method = *no* authentication - username/password is not supported!
    """

    def __init__(self, inbound_address, inbound_port, outbound_address=None):
        """Initializes a Proxy object."""
        super().__init__()
        self.inbound_address = inbound_address
        self.inbound_port = inbound_port
        self.outbound_address = outbound_address
        self.socket_server = SocketServer()  # Costas, composition OK?
        self.should_terminate = False

    def start(self):
        """Starts the SOCKS proxy server."""
        self._logger.debug('starting SOCKS proxy server...')
        self.socket_server.create_socket()
        self.socket_server.listen(self.inbound_port, self.inbound_address)
        self.socket_server.handle_connections()
        threading.Thread(target=self._thread_main_method_per_conn).start()
        return True

    def stop(self):
        """Stops the SOCKS proxy server."""
        self._logger.info("stopping SOCKS proxy server...")
        self.should_terminate = True
        self.socket_server.close_socket()  # this will (also) stop the threaded handle_connections() in SocketServer()
        return True

    def _thread_main_method_per_conn(self):
        while not self.should_terminate:
            if threading.activeCount() > MAX_THREADS:
                sleep(2)
                continue
            if not self.socket_server.connections:
                sleep(1)
                continue
            connection = self.socket_server.connections.pop(0)
            threading.Thread(target=self._negotiate_and_forward_data, args=(connection,)).start()

    def _negotiate_and_forward_data(self, connection):
        """Identifies SOCKS request and forwards data from client to destination.

        o Subnegotiation() is responsible for negotiating version (5) and method (NO AUTH).
        o Communicate() is responsible for forwarding data to destination which can be found in request message.

        """
        self._logger.debug("start SOCKS subnegotiation")
        if Subnegotiation(connection).start():
            self._logger.debug("start handling SOCKS request and forward data")
            RequestHandler(connection, self.outbound_address, self.should_terminate).start()


class RequestHandler(LoggerMixin):
    """Receives DST.ADDR from client ("request"), responds with BND.ADDR ("reply"), and forwards data."""

    def __init__(self,
                 connection,
                 outbound_address,
                 should_terminate):
        """Initializes an Communicate object."""
        super().__init__()
        self.connection = connection
        self.outbound_address = outbound_address
        self.should_terminate = should_terminate
        self.socket_server = SocketServer()
        self.socket_server.create_socket()  # used to make an outgoing connection to destination (eg. web server)

    def _get_destination_address(self):
        """Returns the destination address and port found in the SOCKS request.

        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server and completed the
        method-dependent subnegotiation.

        The SOCKS request is formed as follows:
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        Where:
        o  VER    protocol version: X'05'
        o  CMD
          o  CONNECT X'01'
          o  BIND X'02'
          o  UDP ASSOCIATE X'03'
        o  RSV    RESERVED
        o  ATYP   address type of following address
          o  IP V4 address: X'01'
          o  DOMAINNAME: X'03'
          o  IP V6 address: X'04'
        o  DST.ADDR     desired destination address
        o  DST.PORT     desired destination port in network octet order

        """
        try:
            s5_request = self.connection.recv(BUFSIZE)  # eg. b'\x05\x01\x00\x01\x04\x1f\xc6\x2c\x01\xbb'
            # s5_request[0:1] --> x05 --> 5           VER: SOCKS5
            # s5_request[1:2] --> x01 --> 1           CMD: CONNECT
            # s5_request[2:3] --> x00 --> 0           RSV
            # s5_request[3:4] --> x01 --> 1           ATYP: IPv4
            # s5_request[4:5] --> x04 --> 4           ˥
            # s5_request[5:6] --> x1f --> 31          |  DST.ADDRESS: 4.31.198.44
            # s5_request[6:7] --> xc6 --> 198         |
            # s5_request[7:8] --> x2c --> 44          ˩
            # s5_request[8:10] -> x01xbb -> 1 & 187   DST.PORT: 443 (using format H to read 2 bytes to get to the int.)
        except ConnectionResetError as exp:
            self.connection.close()  # pay attention to this one!
            self._logger.debug("something went wrong: %s", exp)
            return None
        conditions = [s5_request[0:1] != VER,
                      s5_request[1:2] != CMD_CONNECT,
                      s5_request[2:3] != b'\x00']
        if any(conditions):
            return None
        # IPV4
        if s5_request[3:4] == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(s5_request[4:-2])  # '4.31.198.44'
            # socket.inet_ntoa: Convert an IP address from 32-bit (4 bytes) packed binary format to string format
            dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]  # (443,) --> 443
            # struct.unpack: Unpack according to the format string
            # '>' = big-endian byte order and 'H' refers to the size (2, integer) of the packed value
            # alternatively, the following function returns also 443 --> int.from_bytes(b'\x01\xbb', byteorder='big')
        # DOMAIN NAME
        elif s5_request[3:4] == ATYP_DOMAINNAME:
            sz_domain_name = s5_request[4]
            dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
            port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
            dst_port = unpack('>H', port_to_unpack)[0]
        else:
            return None
        return dst_addr, dst_port

    def _send_reply(self, destination_address):
        """Sends a reply in response to a request.

        In the reply to a CONNECT, BND.PORT contains the port number that the
        server assigned to connect to the target host, while BND.ADDR
        contains the associated IP address.

        Server reply:
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+

        Where:
            o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
            o  ATYP   address type of following address
                o  IP V4 address: X'01'  # length 4 octets
                o  DOMAINNAME: X'03'  # first octet of the field contains the number of octets of name that follow
                o  IP V6 address: X'04'  # length 16 octets

        """
        is_reachable = False
        bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
        if destination_address:
            address, port = destination_address
            self.socket_server.set_outbound_address(self.outbound_address)
            is_reachable = self.socket_server.connect_to_socket(address, port)
        if not destination_address or not is_reachable:
            rep = b'\x01'  # failure
            result = False
        else:
            rep = b'\x00'  # success
            result = True
            # getsockname() returns ('37.97.201.241', 60792) and *not* localhost
            bnd = socket.inet_aton(self.socket_server.socket_.getsockname()[0])  # b'%a\xc9\xf1'
            # socket.inet_aton: Convert an IP address in string format to the 32-bit packet binary format
            bnd += pack(">H", self.socket_server.socket_.getsockname()[1])  # b'%a\xc9\xf1\xedx'
            # struct.pack: Return a bytes object packed according to the format string (see unpack above)
        reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
        try:
            self.connection.sendall(reply)
            return result
        except socket.error:
            self.connection.close()  # pay attention to this one!
            result = False
            return result

    def _forward_data(self):
        """Forwards data from client to destination.

        https://steelkiwi.com/blog/working-tcp-sockets/
        Here we call select.select to ask the OS to check given sockets
        whether they are ready to write, read, or if there is some exception respectively.
        That is why it passes three lists of sockets to specify which socket is expected
        to be writable, readable, and which should be checked for errors. This call will
        block the program (unless a timeout argument is passed) until some of the passed sockets are ready

        The select function blocks the thread until data is available
        on a specified socket. Then the data is forwarded to the right recipient.
        """
        self._logger.debug("data from client is being forwarded to destination")
        while not self.should_terminate:
            try:
                reader, _, _ = select.select([self.connection, self.socket_server.socket_], [], [], 1)
            except select.error as err:
                self._logger.debug('select failed: %s', err)
                return None
            if not reader:
                continue
            try:
                for sock in reader:
                    data = sock.recv(BUFSIZE)
                    if not data:
                        return None
                    if sock is self.socket_server.socket_:
                        self.connection.send(data)
                    else:
                        self.socket_server.socket_.send(data)
            except socket.error as err:
                self._logger.debug('proxy loop failed: %s', err)
                return None

    def start(self):
        """Starts communicating."""
        destination_address = self._get_destination_address()
        if self._send_reply(destination_address):
            self._forward_data()
            self.socket_server.close_socket()  # this socket was used to make an outgoing connection
        else:
            self.connection.close()  # pay attention to this one!


class Subnegotiation(LoggerMixin):
    """Negotiates version identifier (5) and method selection (NO AUTH) with client."""

    def __init__(self, connection):
        """Initializes a Subnegotiation object."""
        super().__init__()
        self.connection = connection

    def _retrieve_ver_and_method(self):
        """Retrieves version identifier/method selection.

        The client connects to the SOCKS proxy server, and sends
        a version identifier/method selection message

        Client version identifier/method selection message:
            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     | 1 to 255 |
            +----+----------+----------+

        VER field is set to X'05'

        The values currently defined for METHOD(S) are:
          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'01' GSSAPI
          o  X'02' USERNAME/PASSWORD
          o  X'03' to X'7F' IANA ASSIGNED
          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
          o  X'FF' NO ACCEPTABLE METHODS

        """
        try:
            method_select_packet = self.connection.recv(BUFSIZE)
        except socket.error:
            self._logger.debug("Error")
            return M_NOTAVAILABLE  # b'\xff'
        if VER != method_select_packet[0:1]:
            return M_NOTAVAILABLE
        nmethods = method_select_packet[1]  # the NMETHODS field contains the number of method identifier octets -
        methods = method_select_packet[2:]  # that appear in the METHODS field.
        if len(methods) != nmethods:
            return M_NOTAVAILABLE
        for method in methods:
            if method == ord(M_NOAUTH):
                return M_NOAUTH  # X'00' NO AUTHENTICATION REQUIRED
        return M_NOTAVAILABLE

    def _send_sel_method(self, method):
        """Sends selected method.

        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message.

        Server method selection message:
        +-----+--------+
        | VER | METHOD |
        +-----+--------+
        |  1  |   1    |
        +----+---------+

        """
        if method != M_NOAUTH:
            return False
        reply = VER + method
        try:
            self.connection.sendall(reply)
        except socket.error as exp:
            self._logger.debug("something unexpected happened: %s", exp)
            return False
        self._logger.debug("method-dependent subnegotiation has completed")
        return True

    def start(self):
        """Starts subnegotiation."""
        method = self._retrieve_ver_and_method()
        return self._send_sel_method(method)


def main():
    """Main method."""
    logging.basicConfig(level='DEBUG',
                        filename='/tmp/log',
                        filemode='w',
                        format='%(asctime)s %(name)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    # coloredlogs.install(level='DEBUG')
    agent = Agent(PORT_AGENT)
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
        raise SystemExit(0) from None


if __name__ == "__main__":
    if len(sys.argv) == 2:
        deploy_path = sys.argv[1]
        pid_file = os.path.join(deploy_path, 'agent.pid')
        stdout = os.path.join(deploy_path, 'daemon_out.log')
        stderr = os.path.join(deploy_path, 'daemon_err.log')
        d = Daemon(pid_file=pid_file, stdout=stdout, stderr=stderr)
        d.start(main)
        # main()
    else:
        print("no working path given")
