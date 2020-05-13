#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: transferagent.py
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
Main code for transferagent.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

NOTE: The TransferAgent class is responsible to purge the stream (ie. index in stream is at COMMAND_PROMPT)

"""

import inspect
import logging
import os.path
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
        logger_basename = '''agent'''
        self._logger = logging.getLogger(f'{logger_basename}.{self.__class__.__name__}')


class TransferAgent(LoggerMixin):
    """Establishes a connection to the target destination host via one or more intermediaries."""

    def __init__(self, path_ssh_cfg_minitor, all_hosts):
        """Initialize the TransferAgent object."""
        super().__init__()
        self.all_hosts = all_hosts
        self.child = None
        self.path_ssh_cfg_minitor = path_ssh_cfg_minitor

    def __str__(self):
        return 'TransferAgent'

    def create_ssh_config(self):
        """______________."""
        pass

    @property
    def _path_to_agent_module(self):
        running_script = inspect.getframeinfo(inspect.currentframe()).filename
        running_script_dir = os.path.dirname(os.path.abspath(running_script))
        path_file = os.path.join(running_script_dir, 'payload', 'agent.py')
        self._logger.debug('minitoragent.py resides in: %s', running_script_dir)
        return path_file

    def _generate_ssh_runtime_param(self):
        last_host = self.all_hosts[-1]
        if len(self.all_hosts) == 1:
            order_of_hosts = f'{self.all_hosts[0]}'
        else:
            # the result will be something in this format:
            # scp -F {} -o 'ProxyJump machine1' /home/vincent/Pictures/andy_apollo_imdb.jpg machine2:/tmp
            # scp -F {} -o 'ProxyJump machine1,machine2' /home/vincent/Pictures/andy_apollo_imdb.jpg machine3:/tmp
            order_of_hosts = ''
            for i, host in enumerate(self.all_hosts):
                if i == 0:
                    order_of_hosts += f'{host}'
                else:
                    order_of_hosts += f',{host}'

        runtime_param = f"scp -v -F {self.path_ssh_cfg_minitor} -o 'ProxyJump {order_of_hosts}' " \
                        f"{self._path_to_agent_module} "
        runtime_param += f'{last_host}:/tmp'
        self._logger.debug(runtime_param)
        return runtime_param

    def start(self):
        """_______________________."""
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
                     'not accessible', 'fingerprint', 'open failed: connect failed:', 'No such file', pexpect.TIMEOUT])
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
                    pass
                elif index == 8:
                    self._logger.error('TIMEOUT exception was thrown. ssh could probably not connect to %s', hostname)
                    self.child.terminate()
                    result = False
                else:
                    self._logger.error('unknown state reached')
                    result = False
            # self.child.expect(pexpect.EOF)
        except pexpect.exceptions.ExceptionPexpect:
            self._logger.error('EOF is read; ssh has exited abnormally')
            self.child.terminate()
            result = False
        finally:
            return result
