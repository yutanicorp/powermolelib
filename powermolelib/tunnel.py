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
import threading
from time import sleep
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


class LoggerMixin:  # pylint: disable=too-few-public-methods
    """Contains a logger method for use by other classes."""

    def __init__(self):
        logger_basename = '''Tunnel'''
        self._logger = logging.getLogger(f'{logger_basename}.{self.__class__.__name__}')


class Tunnel(LoggerMixin):  # pylint: disable=too-many-instance-attributes
    """Establishes a connection to the target destination host via one or more intermediaries.

    Be aware, the child's buffer needs to be purged periodically. This can be done by invoking
    periodically_purge_buffer(). As verbose mode is enabled for SSH (the child process), it
    will slowly fill up the buffer, so this has to be taken care of. But don't invoke this
    method before having start()'ed BootstrapAgent.
    """

    def __init__(self, path_ssh_cfg, mode, all_hosts, group_ports,  # pylint: disable=too-many-arguments
                 forward_connections=None):
        """Initialize the Tunnel object."""
        super().__init__()
        self.group_ports = group_ports
        self.forward_connections = forward_connections
        self.mode = mode
        self.all_hosts = all_hosts
        self.path_ssh_cfg = path_ssh_cfg
        self.child = None
        self.thread = None
        self.terminate = False

    def __str__(self):
        return 'Tunnel'

    def _generate_ssh_runtime_param(self):
        # last_host = self.all_hosts[-1]
        last_host = "localhost"
        var_param = None
        if self.mode == 'FOR':
            var_param = f'{self.forward_connections} '
        elif self.mode == 'TOR':
            var_param = f'-L{self.group_ports["local_port_proxy"]}:{last_host}:' \
                        f'{self.group_ports["remote_port_proxy"]} '
        elif self.mode == 'INTERACTIVE':
            var_param = f'-L{self.group_ports["local_port_command"]}:{last_host}:' \
                        f'{self.group_ports["remote_port_command"]} '
        elif self.mode == 'FILE':
            var_param = f'-L{self.group_ports["local_port_transfer"]}:{last_host}:' \
                        f'{self.group_ports["remote_port_transfer"]} '

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

        runtime_param = f'ssh -v -F {self.path_ssh_cfg} ' \
                        f'-L{self.group_ports["local_port_agent"]}:{last_host}:' \
                        f'{self.group_ports["remote_port_agent"]} ' \
                        f'-L{self.group_ports["local_port_heartbeat"]}:{last_host}:' \
                        f'{self.group_ports["remote_port_heartbeat"]} '
        runtime_param += var_param
        runtime_param += f'-J {order_of_hosts}'

        self._logger.debug(runtime_param)
        return runtime_param

    def start(self, debug=None):  # pylint: disable=too-many-branches
        """Starts and controls SSH (child application) along with parameters.

        In addition, this method and mines for 'Authenticated' keywords, so
        we can keep track which hosts have been connected through.

        Args:
            debug(basestring): if True, TIMEOUT will not be raised and may block indefinitely. Use only for debugging
                                purposes to capture the output of the child, which is essentially, hidden 'under the
                                hood', and write it to a file.

        """
        result = True
        try:
            if debug:
                self.child = pexpect.spawn(self._generate_ssh_runtime_param(), env={"TERM": "dumb"}, encoding='utf-8',
                                           timeout=None)
            else:
                self.child = pexpect.spawn(self._generate_ssh_runtime_param(), env={"TERM": "dumb"}, encoding='utf-8')
            # setecho() doesn't seem to have effect.
            #    doc says: Not supported on platforms where isatty() returns False.
            #    perhaps related to the recursive shells (SSH spawns a new shell in the current shell)
            self.child.setecho(False)
            self._logger.debug('going through the stream to match patterns')
            for hostname in self.all_hosts:
                # according to the documentation, "If you wish to read up to the end of the child's output
                #    without generating an EOF exception then use the expect(pexpect.EOF) method."
                #    but apparently this doesn't work in a shell within a shell (ssh spawns a new shell)
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
                    self._logger.error('socket error. probable cause: ssh service on proxy or target machine disabled')
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
            # pylint complains: "return statement in finally block may swallow exception"
            return result

    def stop(self):
        """Closes the tunnel essentially by terminating the program SSH."""
        self.terminate = True
        if self.child.isalive():
            self._logger.debug('ssh is alive, terminating')
            self.child.terminate()
        self._logger.debug('ssh terminated')
        return True

    def debug(self):
        """Captures the output of the child (warning: BLOCKING)."""
        fout = open('/home/vincent/mylog.txt', 'a')
        self.child.logfile = fout
        try:
            self.child.readlines()
        except pexpect.ExceptionPexpect:
            pass

    def periodically_purge_buffer(self):
        """Purges the child's (SSH) output buffer due to buffer limitations."""
        self.thread = threading.Thread(target=self._run_purger)
        self.thread.start()

    def _run_purger(self):
        while not self.terminate:
            try:
                self.child.expect([pexpect.TIMEOUT], timeout=0.2)
                sleep(2)
            except pexpect.exceptions.EOF:
                pass
