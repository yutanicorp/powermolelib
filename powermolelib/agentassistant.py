#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: agentassistant.py
#
# Copyright 2020 Vincent Schouten
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
Main code for agent assistant.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

from abc import ABC, abstractmethod
import socket
from socket import timeout
import os.path
from os.path import basename, dirname
from urllib.error import URLError
import urllib.request
import logging
import json
from time import sleep
from voluptuous import Schema, Required, Any, MultipleInvalid

__author__ = '''Vincent Schouten <inquiry@intoreflection.co>'''
__docformat__ = '''google'''
__date__ = '''10-05-2019'''
__copyright__ = '''Copyright 2020, Vincent Schouten'''
__credits__ = ["Vincent Schouten"]
__license__ = '''MIT'''
__maintainer__ = '''Vincent Schouten'''
__email__ = '''<inquiry@intoreflection.co>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''machine'''
LOGGER = logging.getLogger(LOGGER_BASENAME)  # non-class objects like functions can consult this Logger object

# Constant for Pexpect. This prompt is default for Fedora and CentOS.
COMMAND_PROMPT = '[#$] '

# payload
HTTP_RESPONSE = Schema({Required("result"): Any(True, False)})


class Assistant(ABC):
    """Models an Assistant to interact with the agent residing on target destination host.

    Note: As the agent sits on top of target destination hosts' OS, many functions can be
    performed more effective.

    """

    def __init__(self, tunnel):
        """Initializes the Assistant object."""
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix=self.__class__.__name__)
        self.host_port_proxy_server = tunnel.host_port_proxy_server
        self.host_port_heartbeat_responder = tunnel.host_port_heartbeat_responder
        self.host_port_file_server = tunnel.host_port_file_server
        self.host_port_command_server = tunnel.host_port_command_server
        self.host_port_agent = tunnel.host_port_agent
        self._logger = logging.getLogger(logger_name)
        self.host = '127.0.0.1'  # if card of client

    def __str__(self):
        return 'Assistant'

    def _send_instruction(self, instruction):
        json_instruction = json.dumps(instruction)  # serialize dict to a JSON formatted str
        data = json_instruction.encode('utf-8')  # encode JSON formatted string to byte
        try:
            with urllib.request.urlopen(f'http://{self.host}:{self.host_port_agent}',
                                        timeout=5,
                                        data=data) as request_obj:
                response_string = request_obj.read().decode('utf-8')  # from byte to string (JSON format)
            response_dict = json.loads(response_string)  # from JSON to dict
            response = HTTP_RESPONSE(response_dict)  # validating the structure of the content of an HTTP request
            result = response.get('result')
        except URLError:  # urllib.request.urlopen()
            self._logger.error('agent could not be instructed. probable cause: '
                               'Machine unreachable or client has not connection to the Internet')
            result = False
        except ConnectionResetError:  # urllib.request.urlopen()
            self._logger.error('agent could not be instructed. probable cause: '
                               'agent not bind to port')
            result = False
        except timeout:  # urllib.request.urlopen()
            LOGGER.error('agent could not be instructed. probably cause: '
                         'timeout exceeded for the connection attempt')
            result = False
        except json.decoder.JSONDecodeError:  # json.loads()
            self._logger.error('response of agent could not be read, '
                               'JSON document could not be deserialized')
            result = False
        except MultipleInvalid:  # HTTP_RESPONSE()
            self._logger.error('response of agent could not be read. '
                               'data structure validating failed ("MultipleInvalid")')
            result = False
        return result

    def start_heartbeat_responder(self, machine_local_port):
        """Starts the heartbeat responder."""
        self._logger.debug('instructing the agent to start the heartbeat responder')
        result = self._send_instruction({'process': 'heartbeat_responder_start',
                                         'arguments': {'local_port': machine_local_port}})
        self._logger.debug('agent responded with: %s', result)
        return result

    def stop_heartbeat_responder(self):
        """Stops the heartbeat responder."""
        self._logger.debug('instructing the agent to stop the heartbeat responder')
        result = self._send_instruction({'process': 'heartbeat_responder_stop',
                                         'arguments': {}})
        self._logger.debug('agent responded with: %s', result)
        return result

    def stop_agent(self):
        """Starts the agent."""
        self._logger.debug('instructing agent to stop itself')
        result = self._send_instruction({'process': 'stop',
                                         'arguments': {}})
        self._logger.debug('agent responded with: %s', result)
        return result

    @abstractmethod
    def start(self):
        """Starts the necessary programs on target destination host."""
        pass

    @abstractmethod
    def stop(self):
        """Terminates the started program(s) and the agent on target destination host."""
        pass


class ForAssistant(Assistant):
    """Provides interaction with the agent, which resides on target destination host, to accommodate For mode.

    Functions:
    - interaction with the heartbeat responder
    - forwards connections ('local port forwarding')
    """

    def __init__(self, tunnel):
        """Initializes the ForAssistant object.

        Args:
            tunnel (Tunnel): An instantiated Tunnel object.

        """
        Assistant.__init__(self, tunnel)

    def start(self):
        """Starts the heartbeat responder."""
        return self.start_heartbeat_responder(machine_local_port=self.host_port_heartbeat_responder)

    def stop(self):
        """Terminates minitoragent on target destination host."""
        return self.stop_agent()  # the agent will stop any running services including the heartbeat responder


class TorAssistant(Assistant):
    """Provides interaction with the agent, which resides on target destination host, to accommodate Tor mode.

    Functions:
    - interaction with the heartbeat responder
    - proxify internet traffic
    """

    def __init__(self, tunnel, ip_address_e):
        """Initializes the TorAssistant object.

        Args:
            tunnel (Tunnel): An instantiated Tunnel object.
            ip_address_e (basestring): The IP address on host (on a possible different if) for outgoing connections.

        """
        Assistant.__init__(self, tunnel)
        self.ip_address_e = ip_address_e

    def start_proxy_server(self, machine_local_port, if_address_e):
        """Starts the proxy server."""
        self._logger.debug('instructing the agent to start the proxy server')
        result = self._send_instruction({'process': 'proxy_server_start',
                                         'arguments': {'local_port': machine_local_port,
                                                       'ip_address_e': if_address_e}})
        self._logger.debug('agent responded with: %s', result)
        return result

    def stop_proxy_server(self):
        """Stops the proxy server."""
        self._logger.debug('instructing the agent to stop the proxy server')
        result = self._send_instruction({'process': 'proxy_server_stop',
                                         'arguments': {}})
        self._logger.debug('agent responded with: %s', result)
        return result

    def start(self):
        """Starts the SOCKS proxy and heartbeat responder."""
        return all([self.start_proxy_server(machine_local_port=self.host_port_proxy_server,
                                            if_address_e=self.ip_address_e),
                    self.start_heartbeat_responder(
                        machine_local_port=self.host_port_heartbeat_responder)])

    def stop(self):
        """Terminates the started program(s) and the agent on target destination host."""
        return self.stop_agent()  # the agent will stop any running services including the proxy server


class InteractiveAssistant(Assistant):
    """Provides interaction with the agent, which resides on target destination host, to accommodate Interactive mode.

    Functions:
    - interaction with the heartbeat responder
    - providing an interface
    """

    def __init__(self, tunnel, local_command_port):
        """Initializes the InteractiveAssistant object.

        Args:
            tunnel (Tunnel): An instantiated Tunnel object.
            local_command_port (basestring): <>

        """
        Assistant.__init__(self, tunnel)
        self.local_command_port = local_command_port

    def start(self):
        """Performs authentication of the host and starts the heartbeat responder."""
        return all([self._start_command_server(machine_local_port=self.host_port_command_server),
                    self.start_heartbeat_responder(machine_local_port=self.host_port_heartbeat_responder)])

    def stop(self):
        """Terminates the started program(s) and the agent on target destination host."""
        # if self.probe_agent():
        return self.stop_agent()  # the agent will stop any running services including the command server

    def _start_command_server(self, machine_local_port):
        """Starts the command server."""
        self._logger.debug('instructing the agent to start command server')
        result = self._send_instruction({'process': 'command_server_start',
                                         'arguments': {'local_port': machine_local_port}})
        self._logger.debug('agent responded with: %s', result)
        return result

    def _stop_command_server(self):
        """Stops the command server."""
        self._logger.debug('instructing the agent to stop command server')
        result = self._send_instruction({'process': 'command_server_stop',
                                         'arguments': {}})
        self._logger.debug('agent responded with: %s', result)
        return result

    def exec_command(self, command):
        """Executes Linux command and returns the response in a byte list."""
        if command.lower().strip() == 'exit':
            response = [b'ABORTED: hit control + c to end interactive mode']
            return response
        try:
            command_json = json.dumps({'command': command})  # serialize dict to a JSON formatted str
            command_byte = command_json.encode('utf-8')  # encode JSON formatted string to byte
            with urllib.request.urlopen(f'http://{self.host}:{self.local_command_port}',
                                        timeout=5, data=command_byte) as request_obj:
                # response = request_obj.read().decode('utf-8')  # from byte to string
                response = request_obj.read()
        except URLError:
            self._logger.error('URLError. '
                               'HTTP request could not be send over forwarded connection to agent. '
                               'probable cause: Machine unreachable or client has not connection to the Internet')
            response = False
        except ConnectionResetError:
            self._logger.error('ConnectionResetError. '
                               'HTTP request could not be send over forwarded connection to agent. '
                               'probable cause: agent not bind to port')
            response = False
        except timeout:
            LOGGER.error('HTTP request could not be send over forwarded connection to agent. '
                         'timeout exceeded for the connection attempt. '
                         'probable cause: Machine unreachable or client has not connection to the Internet')
            response = False
        return response


# this class need a redesign!
class FileAssistant(Assistant):
    """Provides interaction with the agent, which resides on target destination host, to accommodate File mode.

    Functions:
    - interaction with the heartbeat responder
    - transfer files.
    """

    def __init__(self, tunnel, local_transfer_port):
        """Initializes the FileAssistant object.

        Args:
            tunnel (Tunnel): An instantiated Tunnel object.
            local_transfer_port (basestring): <>

        """
        Assistant.__init__(self, tunnel)
        self.metadata_files = None
        self.local_transfer_port = local_transfer_port
        self.file_client = None

    def _start_file_server(self, machine_local_port):
        """Starts the file server."""
        self._logger.debug('instructing the minitoragent to start file server')
        result = self._send_instruction({'process': 'file_server_start',
                                         'arguments': {'local_port': machine_local_port}})
        self._logger.debug('minitoragent responded with: %s', result)
        return result

    def _stop_file_server(self):
        """Stops the file server."""
        self._logger.debug('instructing the minitoragent to stop file server')
        result = self._send_instruction({'process': 'file_server_stop',
                                         'arguments': {}})
        if result:
            self._logger.debug('agent has received instruction')
        return result

    def start(self):
        """Starts the heartbeat responder and transfers files."""
        if all([self.start_heartbeat_responder(machine_local_port=self.host_port_heartbeat_responder),
                self._start_file_server(machine_local_port=self.host_port_file_server)]):
            self.file_client = FileClient(local_transfer_port=self.local_transfer_port)
            return self.file_client.start()
        return False

    def transfer(self, metadata_files):
        """Transfers files from client to target destination host."""
        for file in metadata_files:
            # [{'source': '/home/pic1.jpg', 'destination': '/tmp'},
            #  {'source': '/home/pic2.jpg', 'destination': '/tmp'}]
            self.file_client.transfer(file.get('source'), file.get('destination'))
        # the sleep() should be removed and this class should be improved dramatically
        # as soon as the upload has been completed, it sends a terminate signal to agent
        # if the agent is still busy processing the data of the uploaded files
        # it cannot terminates itself successfully and thus the process will stay active
        # with sleep and a magic number the agent gets sufficient time (to be refactored)
        sleep(2)
        self._logger.info('the files are successfully transferred')
        return True

    def stop(self):
        """Terminates the started program(s) and the agent on target destination host."""
        return all([self.file_client.stop(), self.stop_agent()])


class FileClient:  # THIS CLASS HAS TO BE MERGED WITH FILE ASSISTANT !!!
    """Sends files to file server (ie. agent) residing on the target destination host.

    Exclusively used by FileAssistant().

    """

    def __init__(self, local_transfer_port):
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix='FileClient')
        self._logger = logging.getLogger(logger_name)
        self.socket_ = None
        self.local_transfer_port = local_transfer_port

    def start(self):
        """Connects to file server (on Machine) and uploads data."""
        self.socket_ = socket.socket()
        host = 'localhost'
        self.socket_.connect((host, self.local_transfer_port))
        self._logger.debug('connection from client to file server established')
        return True

    def stop(self):
        """Closes socket."""
        self.socket_.close()

    def transfer(self, source, destination):
        """Opens the sockets, connects to file server (ie. agent) on Machine, and sends file(s)."""
        data_protocol = DataProtocol()
        file_name = basename(source)
        path_src = dirname(source)
        path_dst = destination
        try:
            path_dst_bin = data_protocol.path_dst(path_dst=path_dst)
            file_name_bin = data_protocol.file_name(file_name=file_name)
            file_size_bin = data_protocol.file_size(path_src=path_src, file_name=file_name)
            self._send_file(path_src=path_src,
                            file_name=file_name,
                            file_name_bin=file_name_bin,
                            file_size_bin=file_size_bin,
                            path_dst_bin=path_dst_bin)
            self._logger.info('file %s is transferred', source)
        except FileNotFoundError:
            self._logger.error('file or directory is requested but does not exist')
        return True

    def _send_file(self,   # pylint: disable=too-many-arguments
                   path_src,
                   file_name,
                   file_name_bin,
                   file_size_bin,
                   path_dst_bin):
        metadata = path_dst_bin + file_name_bin + file_size_bin  # type is "bytes"
        path_to_file = os.path.join(path_src, file_name)
        self._logger.debug('sending file name, file size and file content')
        data = open(path_to_file, 'rb')  # type is "_io.BufferedReader"
        self.socket_.sendall(metadata + data.read())

    def interrupt(self):  # not implemented, yet
        """Closes the socket."""
        self._logger.debug('interrupting the transfer of binary data.')
        return True


class DataProtocol:
    """Encodes file metadata to a binary format."""

    def __init__(self):
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix='DataProtocol')
        self._logger = logging.getLogger(logger_name)

    def path_dst(self, path_dst):
        """Encodes the destination path."""
        self._logger.debug('path to directory on remote server: %s', path_dst)
        length_path_int = len(path_dst)
        length_path_bin = bin(length_path_int)[2:].zfill(16)  # (str) from decimal to binary (eg. 0000000000001110)
        return length_path_bin.encode('utf-8') + path_dst.encode('utf-8')  # binary

    def file_name(self, file_name):
        """Encodes (only) the file name - not the directory."""
        self._logger.debug('name of file to be transferred: %s', file_name)
        length_file_int = len(file_name)
        length_file_bin = bin(length_file_int)[2:].zfill(16)  # (str) from dec to bin + pad with zeros to fill w=16b
        return length_file_bin.encode('utf-8') + file_name.encode('utf-8')  # (binary)

    def file_size(self, path_src, file_name):
        """Encodes the file size."""
        path_to_file = os.path.join(path_src, file_name)
        size_file_int = os.path.getsize(path_to_file)
        self._logger.debug('size of file %s: %s bytes', file_name, size_file_int)
        size_file_bin = bin(size_file_int)[2:].zfill(32)  # (str) from dec to bin + pad with zeros to fill width of 32b
        return size_file_bin.encode('utf-8')
