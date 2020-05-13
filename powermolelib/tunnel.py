#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: tunnel.py
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
Main code for tunnel.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

NOTE: The Tunnel classes are responsible to purge the stream (ie. index in stream is at COMMAND_PROMPT)

"""

# from abc import ABC, abstractmethod
import logging
import pexpect

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

# Constants, port numbers
LOCAL_HEARTBEAT_PORT = 11600  # local port used by the heartbeat mechanism to communicate with agent (all modes)
LOCAL_AGENT_PORT = 44191  # local (forwarded) used by program to send instructions to agent (all modes)
LOCAL_COMMAND_PORT = 11800  # local port used by program to send linux commands to agent (only in INTERACTIVE mode)
LOCAL_PROXY_PORT = 8080  # local port used to forward web traffic which exits destination host (only in TOR mode)
LOCAL_TRANSFER_PORT = 11700  # local port used by minitor to upload files to destination host (only in FILE mode)


class LoggerMixin:  # pylint: disable=too-few-public-methods
    """Contains a logger method for use by other classes."""

    def __init__(self):
        logger_basename = '''agent'''
        self._logger = logging.getLogger(f'{logger_basename}.{self.__class__.__name__}')


class Tunnel(LoggerMixin):
    """Establishes a connection to the target destination host via one or more intermediaries."""

    def __init__(self, path_ssh_cfg_minitor, mode, all_hosts, forward_connections=None):
        """Initialize the Tunnel object."""
        super().__init__()
        self.host_port_proxy_server = 44192
        self.host_port_heartbeat_responder = 44193
        self.host_port_file_server = 44194
        self.host_port_command_server = 44195
        self.host_port_agent = 44191
        self.forward_connections = forward_connections
        self.mode = mode
        self.all_hosts = all_hosts
        self.child = None
        self.local_agent_port = LOCAL_AGENT_PORT
        self.local_heartbeat_port = LOCAL_HEARTBEAT_PORT
        self.path_ssh_cfg_minitor = path_ssh_cfg_minitor

    def __str__(self):
        return 'Tunnel'

    def _generate_ssh_runtime_param(self):
        last_host = self.all_hosts[-1]
        var_param = None
        if self.mode == 'FOR':
            var_param = f'{self.forward_connections} '
        elif self.mode == 'TOR':
            var_param = f'-L{LOCAL_PROXY_PORT}:{last_host}:{self.host_port_proxy_server} '
        elif self.mode == 'INTERACTIVE':
            var_param = f'-L{LOCAL_COMMAND_PORT}:{last_host}:{self.host_port_command_server} '
        elif self.mode == 'FILE':
            var_param = f'-L{LOCAL_TRANSFER_PORT}:{last_host}:{self.host_port_file_server} '

        if len(self.all_hosts) == 2:
            order_of_hosts = f'{self.all_hosts[0]} {self.all_hosts[1]}'
        else:
            # the result will be something in this format 'machine1,machine2,machine3 machine4'
            order_of_hosts = ''
            for i, host in enumerate(self.all_hosts):
                if i == 0:
                    order_of_hosts += f'{host}'
                elif i < len(self.all_hosts) - 1:
                    order_of_hosts += f',{host}'
                else:
                    order_of_hosts += f' {host}'

        runtime_param = f'ssh -v -F {self.path_ssh_cfg_minitor} ' \
                        f'-L{LOCAL_AGENT_PORT}:{last_host}:{self.host_port_agent} ' \
                        f'-L{LOCAL_HEARTBEAT_PORT}:{last_host}:{self.host_port_heartbeat_responder} '
        runtime_param += var_param
        runtime_param += f'-J {order_of_hosts}'

        self._logger.debug(runtime_param)
        return runtime_param

    def start(self):
        """__________________."""
        result = True
        try:
            self.child = pexpect.spawn(self._generate_ssh_runtime_param(), env={"TERM": "dumb"})
            # self.process.setecho(False)  # doesn't seem to have effect
            # self.process.waitnoecho()  # doesn't seem to have effect
            self._logger.debug('going through the stream to match patterns')
            for hostname in self.all_hosts:
                # according to the documentation, "If you wish to read up to the end of the child's output -
                #         # without generating an EOF exception then use the expect(pexpect.EOF) method."
                #         # but apparently this doesn't work in a shell within a shell (ssh spawns a new shell)
                index = self.child.expect(
                    [f'Authenticated to {hostname}', 'Last failed login:', 'Last login:', 'socket error',
                     'not accessible', 'fingerprint', 'open failed: connect failed:', pexpect.TIMEOUT])
                if index == 0:
                    self._logger.info('authenticated to %s', hostname)
                elif index == 1:
                    self._logger.debug('there were failed login attempts')
                elif index == 2:
                    self._logger.debug('there where no failed login attempts')
                elif index == 3:
                    self._logger.error('socket error. probable cause: SSH service on proxy or target machine disabled')
                    self.child.terminate()
                    result = False
                elif index == 4:
                    self._logger.error('the identity file is not accessible')
                    self.child.terminate()
                    result = False
                elif index == 5:
                    self._logger.warning('warning: hostname automatically added to list of known hosts')
                    self.child.sendline('yes')
                elif index == 6:
                    self._logger.error('ssh could not connect to %s', hostname)
                    self.child.terminate()
                    result = False
                elif index == 7:
                    self._logger.error('TIMEOUT exception was thrown. ssh could probably not connect to %s', hostname)
                    self.child.terminate()
                    result = False
                else:
                    self._logger.error('unknown state reached')
                    result = False
            self.child.expect(COMMAND_PROMPT)
        except pexpect.exceptions.ExceptionPexpect:
            self._logger.error('EOF is read; ssh has exited abnormally')
            self.child.terminate()
            result = False
        finally:
            return result

    def stop(self):
        """Closes the tunnel essentially by terminating the program SSH."""
        if self.child.isalive():
            self._logger.debug('ssh is alive, terminating')
            self.child.terminate()
        self._logger.debug('ssh terminated')
        return True
