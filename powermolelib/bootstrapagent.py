#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: bootstrapagent.py
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
Main code for bootstrapping agent.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

NOTE: The BootstrapAgent class is responsible to purge the stream (ie. index in stream is at COMMAND_PROMPT)

"""

from socket import timeout
import os.path
from urllib.error import URLError
import urllib.request
from time import sleep
import json
import pexpect
from voluptuous import Schema, Required, Any, MultipleInvalid
from .logging import LoggerMixin

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


class BootstrapAgent(LoggerMixin):
    """Responsible for executing the python agent module."""

    def __init__(self, tunnel, group_ports, deploy_path='/tmp'):
        """Initializes the BootstrapAgent object.

        Args:
            tunnel (Tunnel): An instantiated Tunnel object.
            group_ports (dict): Port names with port numbers.
            deploy_path (str): Path where the agent.py module (Agent) resides.

        """
        super().__init__()
        self.tunnel = tunnel
        self.local_port_agent = group_ports["local_port_agent"]
        self.host = '127.0.0.1'  # localhost, client
        self.deploy_path = deploy_path
        self.path_to_agent = os.path.join(self.deploy_path, 'agent.py')

    def __str__(self):
        return 'BootstrapAgent'

    def start(self):
        """Executes the agent python module (after checking for availability and running process)."""
        result = False
        if self._is_python3_available():
            if self.is_agent_module_available():
                if self._can_agent_be_probed():
                    if not self._instruct_stop_agent():
                        self._logger.warning('running Agent could not be instructed to stop')
                        if self._is_process_alive():
                            self._killing_process()
                            self._logger.warning('running Agent process has been killed')
                else:
                    if self._is_process_alive():
                        self._killing_process()
                        self._logger.warning('running Agent process has been killed')
                result = self._execute_agent()
        return result

    def _is_python3_available(self):
        """Determines if python 3 binary is available."""
        result = False
        # command = f"pgrep -fc '/bin/python3 {self.path_to_agent}'"
        command = '/bin/python3 -V; echo $?'
        self._logger.debug('probing if Python 3 binary exists by requesting version %s', command)
        self.tunnel.child.sendline(command)
        index = self.tunnel.child.expect(['0', '127', pexpect.TIMEOUT], timeout=3)
        self.tunnel.child.expect(COMMAND_PROMPT)
        if index == 0:
            self._logger.debug('Python 3 is available')
            result = True
        if index == 1:
            self._logger.debug('Python 3 is not available!')
        return result

    def _can_agent_be_probed(self):
        """Determines whether the agent is listening thus active on target destination host."""
        result = False
        self._logger.debug('determining if Agent is alive by sending a GET request')
        try:
            with urllib.request.urlopen(f'http://{self.host}:{self.local_port_agent}',
                                        timeout=3, data=None) as request_obj:
                http_code = request_obj.getcode()
                if http_code == 200:
                    self._logger.debug('Agent is alive')
                    result = True
        except (ConnectionResetError, URLError, timeout) as exp:
            self._logger.debug('sending request raised an error: %s', exp)
        return result

    def _remove_remnants(self):
        command = f"rm -f {self.deploy_path}agent.pid"
        self._logger.debug('removing pid file, if present: %s', command)
        self.tunnel.child.sendline(command)
        self.tunnel.child.expect(COMMAND_PROMPT)

    def _is_process_alive(self):
        """Determines if an Agent process is (still) running."""
        result = False
        # command = f"pgrep -fc '/bin/python3 {self.path_to_agent}'"
        command = f'if [ `pgrep -fc \'/bin/python3 {self.path_to_agent}\'` == 0 ]; ' \
                  f'then echo "count=0"; else echo "count=1"; fi'
        self._logger.debug('determining if an Agent process is (still) running: %s', command)
        self.tunnel.child.sendline(command)
        # self.tunnel.child.logfile = sys.stdout
        index = self.tunnel.child.expect(['count=0', 'count=1', pexpect.TIMEOUT], timeout=3)
        self.tunnel.child.expect(COMMAND_PROMPT)
        if index == 0:
            self._logger.debug('no Agent process is running')
            self._remove_remnants()
        if index == 1:
            self._logger.debug('an Agent process is (still) running on destination host')
            result = True
        return result

    def _killing_process(self):
        """Kills the Agent process."""
        command = f"pkill -f '/bin/python3 {self.path_to_agent}'"
        self._logger.debug('killing running agent.py process: %s', command)
        self.tunnel.child.sendline(command)
        self.tunnel.child.expect(COMMAND_PROMPT)
        while self._is_process_alive():
            self._logger.debug('waiting for OS to successfully kill process... ')
            sleep(4)
        sleep(1)
        return True

    def _instruct_stop_agent(self):
        """Stops the Agent by sending a 'process:stop' request."""
        result = False
        json_instruction = json.dumps({'process': 'stop',
                                       'arguments': {}})  # serialize dict to a JSON formatted str
        data = json_instruction.encode('utf-8')  # encode JSON formatted string to byte
        try:
            with urllib.request.urlopen(f'http://{self.host}:{self.local_port_agent}',
                                        timeout=3, data=data) as request_obj:
                response_string = request_obj.read().decode('utf-8')  # from byte to string (JSON format)
            response_dict = json.loads(response_string)  # from JSON to dict
            response = HTTP_RESPONSE(response_dict)  # validating the structure of the content of an HTTP request
            result = response.get('result')
            if result:
                self._logger.debug('Agent has received instruction to stop')
                result = True
        except (ConnectionResetError, URLError, timeout) as exp:  # urllib.request.urlopen()
            self._logger.debug('instructing the Agent raised an error: %s', exp)
        except json.decoder.JSONDecodeError:  # json.loads()
            self._logger.error('response of Agent could not be read: JSON document could not be deserialized')
        except MultipleInvalid:  # HTTP_RESPONSE()
            self._logger.error('response of Agent could not be read: data structure validating failed')
        sleep(2)  # give the Agent time to terminate servers
        return result

    def is_agent_module_available(self):
        """Determines if agent.py module is on target destination host."""
        self.tunnel.child.sendline(f'file {self.path_to_agent}')
        index = self.tunnel.child.expect(['Python script', 'cannot open'])
        if index == 0:
            self._logger.debug('module agent.py is available on host')
            result = True
        else:
            self._logger.error('module agent.py is not available on host')
            result = False
        self.tunnel.child.expect(COMMAND_PROMPT)
        return result

    def _execute_agent(self):
        """Executes agent.py module on target destination host."""
        command = f'/bin/python3 {self.path_to_agent} {self.deploy_path}'
        self._logger.debug('executing the Agent module with command: %s', command)
        self.tunnel.child.sendline(command)
        index = self.tunnel.child.expect([COMMAND_PROMPT, 'SyntaxError', 'ModuleNotFoundError', 'AttributeError',
                                          'pid exists', pexpect.TIMEOUT], timeout=3)
        if index == 0:
            result = True
            sleep(2)  # The Agent needs some time to initialize, so wait with returning the Boolean result
        elif index == 1:
            self._logger.error(
                'check if Python version 3.6 or higher is installed on destination host. '
                'the command was: %s', command)
            result = False
        elif index == 4:
            self._logger.error(
                'agent.py could not be executed. '
                'it seems the Agent is running due to the existence of the PID file.'
                'the command was: %s', command)
            result = False
        else:
            self._logger.error(
                'agent.py could not be executed. '
                'try running %s on destination host manually to determine the cause',
                command)
            result = False
        return result

    def remove(self):
        """Removes the python Agent module (not implemented, yet)."""
        # pass
