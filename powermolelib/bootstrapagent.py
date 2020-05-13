#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: bootstrapagent.py
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
Main code for bootstrapping minitoragent.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

NOTE: The BootstrapAgent class is responsible to purge the stream (ie. index in stream is at COMMAND_PROMPT)

"""

# TODO: make the transfer methods of FileMachine en FileClient unique. pylint: disable=fixme

from socket import timeout
import os.path
from urllib.error import URLError
import urllib.request
from time import sleep
import logging
import json
import pexpect
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

# Constant for Pexpect. This prompt is default for Fedora and CentOS.
COMMAND_PROMPT = '[#$] '

# Constants for agents or agent assistant
LOCAL_AGENT_PORT = 44191  # local (forwarded) port on client that program uses to send instructions to agent

# payload
HTTP_RESPONSE = Schema({Required("result"): Any(True, False)})


class LoggerMixin:  # pylint: disable=too-few-public-methods
    """Contains a logger method for use by other classes."""

    def __init__(self):
        logger_basename = '''agent'''
        self._logger = logging.getLogger(f'{logger_basename}.{self.__class__.__name__}')


class BootstrapAgent(LoggerMixin):
    """Responsible for executing the python agent module."""

    def __init__(self, tunnel, deploy_path):
        super().__init__()
        self.tunnel = tunnel
        self.local_port_agent = LOCAL_AGENT_PORT
        self.host = '127.0.0.1'  # localhost, client
        self.deploy_path = deploy_path
        self.path_to_agent = os.path.join(self.deploy_path, 'agent.py')

    def __str__(self):
        return 'BootstrapAgent'

    def start(self):
        """Starts the agent (after checking for availability and running process)."""
        result = False
        if self.check_availability_agent_module():
            self.stop_possible_running_agent()
            result = self.execute_agent()
            return result
        return result

    def _probe_agent(self):
        """Determines whether the agent is listening thus active on target destination host."""
        http_code = 0
        result = False
        self._logger.debug('checking if agent is alive by sending a GET request')
        try:
            with urllib.request.urlopen(f'http://{self.host}:{self.local_port_agent}',
                                        timeout=3, data=None) as request_obj:
                http_code = request_obj.getcode()
            if http_code == 200:
                result = True
        except URLError:
            self._logger.debug('agent could not be probed. '
                               'probable cause: Machine unreachable or client has not connection to the Internet.')
            result = False
        except ConnectionResetError:
            self._logger.debug('agent could not be probed. '
                               'probable cause: minitoragent not bind to port or SSH process got killed')
            result = False
        except timeout:
            self._logger.error('agent could not be probed. '
                               'timeout exceeded for the connection attempt. '
                               'probable cause: Machine unreachable or client has not connection to the Internet')
            result = False
        finally:
            pass
        return result

    def _killing_process(self):
        self._logger.debug('killing any running agent process(es), if present')
        command = f"pkill -f 'python {self.path_to_agent}'"
        self.tunnel.child.sendline(command)
        self.tunnel.child.expect(COMMAND_PROMPT)

    def _stop_agent(self):
        json_instruction = json.dumps({'process': 'stop',
                                       'arguments': {}})  # serialize dict to a JSON formatted str
        data = json_instruction.encode('utf-8')  # encode JSON formatted string to byte
        try:
            with urllib.request.urlopen(f'http://{self.host}:{self.local_port_agent}',
                                        timeout=3,
                                        data=data) as request_obj:
                response_string = request_obj.read().decode('utf-8')  # from byte to string (JSON format)
            response_dict = json.loads(response_string)  # from JSON to dict
            response = HTTP_RESPONSE(response_dict)  # validating the structure of the content of an HTTP request
            result = response.get('result')
            if result:
                self._logger.debug('agent has received instruction')
        except URLError:  # urllib.request.urlopen()
            self._logger.error('agent could not be instructed. probable cause: '
                               'Machine unreachable or client has not connection to the Internet')
            result = False
        except ConnectionResetError:  # urllib.request.urlopen()
            self._logger.error('agent could not be instructed. probable cause: '
                               'agent not bind to port')
            result = False
        except timeout:  # urllib.request.urlopen()
            self._logger.error('agent could not be instructed. probably cause: '
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

    def check_availability_agent_module(self):
        """Determines if agent.py module is on target destination host."""
        self.tunnel.child.sendline(f'file {self.path_to_agent}')
        index = self.tunnel.child.expect(['Python script', 'cannot open'])
        self.tunnel.child.expect(COMMAND_PROMPT)
        if index == 0:
            self._logger.debug('module minitoragent.py is available on Machine')
            result = True
        else:
            self._logger.error('module minitoragent.py is not available on Machine')
            result = False
        return result

    def stop_possible_running_agent(self):
        """Determines if agent.py module is still running on target destination host."""
        if self._probe_agent():
            self._logger.debug('the agent is still running. trying to terminate gracefully...')
            self._stop_agent()
            while True:
                # the minitoragent (or rather the OS) needs some time to free up socket, so check, wait, repeat, stop
                command = f"pgrep -fc 'python {self.path_to_agent}'"
                self.tunnel.child.sendline(command)
                index = self.tunnel.child.expect(['0', '1', pexpect.TIMEOUT], timeout=3)
                if index == 0:
                    break
                sleep(1.2)  # the python process is still running, wait, and check again.
            self._logger.debug('the process of agent has been terminated')
        else:
            self._logger.debug('there is no indicator of a running python process (for the agent)')
            self._killing_process()  # to be absolutely sure

    def execute_agent(self):
        """Executes agent.py module on target destination host."""
        command = f'/bin/python3.6 {self.path_to_agent} {self.deploy_path}'
        self._logger.debug('executing the agent module, command: %s', command)
        self.tunnel.child.sendline(command)
        index = self.tunnel.child.expect([COMMAND_PROMPT, 'SyntaxError', 'ModuleNotFoundError', 'AttributeError',
                                          'pid exists', pexpect.TIMEOUT], timeout=3)
        if index == 0:
            result = True
            sleep(2)  # The minitoragent needs some time to initialize, so wait with returning the Boolean result
        elif index == 1:
            self._logger.error(
                'check if Python version 3.6 is installed on destination host. '
                'the command was: %s', command)
            result = False
        elif index == 4:
            self._logger.error(
                'minitoragent.py could not be executed. '
                'it seems the Agent is running due to the existence of the '
                'PID file. the command was: %s', command)
            result = False
        else:
            self._logger.error(
                'minitoragent.py could not be executed. '
                'try running %s on destination host manually to determine the cause',
                command)
            result = False
        return result

    def remove(self):
        """Removes the python agent module (not implemented, yet)."""
        pass
