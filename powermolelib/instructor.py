#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: instructor.py
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
Main code for instructor.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import urllib.request
import json
from socket import timeout
from abc import ABC, abstractmethod
from urllib.error import URLError
from voluptuous import Schema, Required, Any, MultipleInvalid
from .logging import LoggerMixin
from .payload.agent import DataProtocol
from .powermolelibexceptions import InvalidDataStructure

__author__ = '''Vincent Schouten <powermole@protonmail.com>'''
__docformat__ = '''google'''
__date__ = '''10-05-2019'''
__copyright__ = '''Copyright 2021, Vincent Schouten'''
__credits__ = ["Vincent Schouten"]
__license__ = '''MIT'''
__maintainer__ = '''Vincent Schouten'''
__email__ = '''<powermole@protonmail.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# Constant for Pexpect. This prompt is default for Fedora and CentOS.
COMMAND_PROMPT = '[#$] '

# payload
HTTP_RESPONSE = Schema({Required("result"): Any(True, False)})


def validate_transfer_server_response(response):
    """Validates the data structure of the content of an incoming HTTP request.

    These requests are received by the CommandServer and contains Linux commands.
    """
    if all([isinstance(response.get('process'), str),
            isinstance(response.get('status_code'), int)]):
        return response.get('process'), response.get('status_code')
    raise InvalidDataStructure


class Instructor(ABC, LoggerMixin):
    """Models an Instructor to interact with the Agent residing on target destination host.

    Note: As the Agent sits on top of target destination hosts' OS, many functions can be
    performed more effectively.

    """

    def __init__(self, group_ports):
        """Initializes the Instructor object."""
        super().__init__()
        self.group_ports = group_ports
        self.host = '127.0.0.1'  # if-card of client
        self.socket_ = None

    def __str__(self):
        return 'Instructor'

    def _send_instruction(self, instruction):
        json_instruction = json.dumps(instruction)  # serialize dict to a JSON formatted str
        data = json_instruction.encode('utf-8')  # encode JSON formatted string to byte
        self._logger.debug('sending via %s:%s the following instruction: %s',
                           self.host, self.group_ports["local_port_agent"], data)
        try:
            with urllib.request.urlopen(f'http://{self.host}:{self.group_ports["local_port_agent"]}',
                                        timeout=5,
                                        data=data) as request_obj:
                response_string = request_obj.read().decode('utf-8')  # from byte to string (JSON format)
            response_dict = json.loads(response_string)  # from JSON to dict
            response = HTTP_RESPONSE(response_dict)  # validating the structure of the content of an HTTP request
            result = response.get('result')
        except URLError:  # urllib.request.urlopen()
            self._logger.error('something went wrong when instructing the Agent, probably host unreachable')
            result = False
        except ConnectionResetError:  # urllib.request.urlopen()
            self._logger.error('connection is reset: Agent is probably not alive')
            result = False
        except timeout:  # urllib.request.urlopen()
            self._logger.error('timeout exceeded when instructing the Agent')
            result = False
        except json.decoder.JSONDecodeError:  # json.loads()
            self._logger.error('response of Agent could not be read, '
                               'JSON document could not be deserialized')
            result = False
        except MultipleInvalid:  # HTTP_RESPONSE()
            self._logger.error('response of Agent could not be read. '
                               'data structure validating failed ("MultipleInvalid")')
            result = False
        return result

    def _start_heartbeat_responder(self, host_port):
        """Sends the instruction to Agent to start the heartbeat responder."""
        return self._start_server(host_port, 'heartbeat_responder_start', 'heartbeat responder')

    def _start_command_server(self, host_port):
        """Starts the command server."""
        return self._start_server(host_port, 'command_server_start', 'command server')

    def _start_transfer_server(self, host_port):  # Costas, I've changed this method
        """Starts the transfer server."""
        # return self._start_server(host_port, 'transfer_server_start', 'transfer server')
        self._logger.debug('instructing Agent to start %s', 'transfer server')
        result = self._send_instruction({'process': 'transfer_server_start',
                                         'arguments': {'mode': 'receive',
                                                       'port': host_port}})
        self._logger.debug('Agent responded with: %s', result)
        return result

    def _start_server(self, host_port, process, message):
        """Starts the transfer server."""
        self._logger.debug('instructing Agent to start %s', message)
        result = self._send_instruction({'process': process,
                                         'arguments': {'port': host_port}})
        self._logger.debug('Agent responded with: %s', result)
        return result

    # def start_agent(self):
    #     print("the BootstrapAgent-module is responsible for starting agent.py (Agent) on destination host")

    def stop_agent(self):
        """Starts the Agent on destination host."""
        self._logger.debug('instructing Agent to stop itself')
        result = self._send_instruction({'process': 'stop',
                                         'arguments': {}})
        self._logger.debug('Agent responded with: %s', result)
        return result

    def send_command(self, command):
        """Executes Linux command and returns the response in a byte list."""
        if command.lower().strip() == 'exit':
            response = [b'ABORTED: hit control + c to end interactive mode']
            return response
        try:
            command_json = json.dumps({'command': command})  # serialize dict to a JSON formatted str
            command_byte = command_json.encode('utf-8')  # encode JSON formatted string to byte
            with urllib.request.urlopen(f'http://{self.host}:{self.group_ports["local_port_command"]}',
                                        timeout=5, data=command_byte) as request_obj:
                # response = request_obj.read().decode('utf-8')  # from byte to string
                response = request_obj.read()
        except URLError as exp:
            self._logger.error('instructing the Agent raised an error: %s', exp)
            response = False
        except ConnectionResetError as exp:
            self._logger.error('instructing the Agent raised an error: %s', exp)
            response = False
        except timeout:
            self._logger.error('timeout exceeded when instructing the Agent')
            response = False
        return response

    def send_file(self, src_file_path, dest_path):
        """Opens the socket and connects to transfer server (ie. Agent) and sends a file."""
        port = self.group_ports["local_port_transfer"]
        data_protocol = DataProtocol('send', port)
        data_protocol.start()
        self._logger.debug('connection from client to transfer server by Agent on destination host established')
        result = False
        try:
            if data_protocol.send_metadata(src_file_path, dest_path):
                data_protocol.send_file(src_file_path)
                result = True
        except FileNotFoundError:
            self._logger.error('file or directory does not exist on client')
        data_protocol.stop()
        return result  # lost-exception / return statement in finally block may swallow exception (col 12)

    @abstractmethod
    def start(self):
        """Starts the necessary programs on target destination host."""

    @abstractmethod
    def stop(self):
        """Terminates the started program(s) and the Agent on target destination host."""


class ForInstructor(Instructor):
    """Provides interaction with the Agent, which resides on target destination host, to accommodate FOR mode.

    Functions:
    - forwards connections (FOR) implicitly, because SSH is responsible for forwarding connections, not the Agent
    - interaction with the heartbeat responder
    - provide access to OS services (COMMAND)
    - transfer files (TRANSFER)
    """

    def __init__(self, group_ports):
        """Initializes the ForInstructor object.

        Args:
            group_ports (dict): A group of ports for powermole to bind on (localhost and target destination host)

        """
        Instructor.__init__(self, group_ports)

    def start(self):
        """Starts the heartbeat responder."""
        return all([self._start_heartbeat_responder(host_port=self.group_ports["remote_port_heartbeat"]),
                    self._start_command_server(host_port=self.group_ports["remote_port_command"]),
                    self._start_transfer_server(host_port=self.group_ports["remote_port_transfer"])])

    def stop(self):
        """Terminates the Agent on destination host and started services (heartbeat responder, command server, etc)."""
        return self.stop_agent()


class TorInstructor(Instructor):
    """Provides interaction with the Agent, which resides on target destination host, to accommodate Tor mode.

    Functions:
    - proxify internet traffic (TOR)
    - interaction with the heartbeat responder
    - provide access to OS services (COMMAND)
    - transfer files (TRANSFER)
    """

    def __init__(self, group_ports, outbound_address, inbound_address='localhost'):
        """Initializes the TorInstructor object.

        Args:
            group_ports (dict): A group of ports for powermole to bind on (localhost and target destination host)
            inbound_address (basestring): The IP address on host for incoming SOCKS encapsulated connections.
            outbound_address (basestring): The IP address on host (on a possible other if) for outgoing connections.

        """
        Instructor.__init__(self, group_ports)
        self.inbound_address = inbound_address
        self.outbound_address = outbound_address

    def _start_proxy_server(self, inbound_address, inbound_port, outbound_address):
        """Sends an instruction to Agent to start the proxy server."""
        self._logger.debug('instructing Agent to start the proxy server')
        result = self._send_instruction({'process': 'proxy_server_start',
                                         'arguments': {'inbound_address': inbound_address,
                                                       'inbound_port': inbound_port,
                                                       'outbound_address': outbound_address}})
        self._logger.debug('Agent responded with: %s', result)
        return result

    def start(self):
        """Starts the SOCKS proxy and heartbeat responder."""
        return all([self._start_proxy_server(inbound_address=self.inbound_address,
                                             inbound_port=self.group_ports["remote_port_proxy"],
                                             outbound_address=self.outbound_address),
                    self._start_heartbeat_responder(host_port=self.group_ports["remote_port_heartbeat"]),
                    self._start_command_server(host_port=self.group_ports["remote_port_command"]),
                    self._start_transfer_server(host_port=self.group_ports["remote_port_transfer"])])

    def stop(self):
        """Terminates the Agent on destination host and all started services (heartbeat responder, proxy server, ..)."""
        return self.stop_agent()


class PlainInstructor(Instructor):
    """Provides interaction with the Agent, which resides on target destination host, to accommodate FOR mode.

    Functions:
    - interaction with the heartbeat responder
    - provide access to OS services (COMMAND)
    - transfer files (TRANSFER)
    """

    def __init__(self, group_ports):
        """Initializes the ForInstructor object.

        Args:
            group_ports (dict): A group of ports for powermole to bind on (localhost and target destination host)

        """
        Instructor.__init__(self, group_ports)

    def start(self):
        """Starts the heartbeat responder."""
        return all([self._start_heartbeat_responder(host_port=self.group_ports["remote_port_heartbeat"]),
                    self._start_command_server(host_port=self.group_ports["remote_port_command"]),
                    self._start_transfer_server(host_port=self.group_ports["remote_port_transfer"])])

    def stop(self):
        """Terminates the Agent on destination host and started services (heartbeat responder, command server, etc)."""
        return self.stop_agent()
