#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: miscellaneous.py
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
Main code for miscellaneous.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""
import json
import logging
import logging.config
import threading
import subprocess
from urllib.error import URLError
import urllib.request
from time import sleep
from socket import timeout
from voluptuous import Schema, Required, Any, REMOVE_EXTRA, Optional, MultipleInvalid
from .powermolelibexceptions import InvalidConfigurationFile

__author__ = '''Vincent Schouten <inquiry@intoreflection.co>'''
__docformat__ = '''google'''
__date__ = '''10-05-2019'''
__copyright__ = '''Copyright 2020, Vincent Schouten'''
__license__ = '''MIT'''
__maintainer__ = '''Vincent Schouten'''
__email__ = '''<inquiry@intoreflection.co>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging.
logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
LOGGER_BASENAME = '''helpers'''
LOGGER = logging.getLogger(LOGGER_BASENAME)  # non-class objects like functions will consult this Logger object

# Constants
HEARTBEAT_DURATION = 5

MODE_SCHEMA = Schema({Required("mode"): Any("TOR", "FOR", "INTERACTIVE", "FILE"),
                      }, extra=REMOVE_EXTRA)

TOR_SCHEMA = Schema({"mode": "TOR",
                     "gateways": [{"host_ip": str,
                                   "user": str,
                                   "identity_file": str}],
                     "destination": {"host_ip": str,
                                     "user": str,
                                     "identity_file": str},
                     Optional("application"): {"binary_name": str,
                                               "binary_location": str}
                     }, required=True)

FOR_SCHEMA = Schema({"mode": "FOR",
                     "gateways": [{"host_ip": str,
                                   "user": str,
                                   "identity_file": str}],
                     "destination": {"host_ip": str,
                                     "user": str,
                                     "identity_file": str},
                     "forwarders": [{"local_port": int,
                                     "remote_interface": str,
                                     "remote_port": int}],
                     Optional("application"): {"binary_name": str,
                                               "binary_location": str}
                     }, required=True)

INTERACTIVE_SCHEMA = Schema({"mode": "INTERACTIVE",
                             "gateways": [{"host_ip": str,
                                           "user": str,
                                           "identity_file": str}],
                             "destination": {"host_ip": str,
                                             "user": str,
                                             "identity_file": str},
                             }, required=True)

FILE_SCHEMA = Schema({"mode": "FILE",
                      "gateways": [{"host_ip": str,
                                    "user": str,
                                    "identity_file": str}],
                      "destination": {"host_ip": str,
                                      "user": str,
                                      "identity_file": str},
                      "files": [{"source": str,
                                 "destination": str}]
                      }, required=True)


class Configuration:  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    """Parses the configuration file."""

    def __init__(self, config_file):
        """Initializes the Configuration object.

        Args:
            config_file(basestring): A file containing a JSON document.

        """
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix='Configuration')
        self._logger = logging.getLogger(logger_name)
        try:
            config = self.get_config(config_file)
            self.mode = config.get('mode')
            self.gateways = config.get('gateways')
            # ex. [{'host_ip': '10.10.1.72', 'user': 'root', 'identity_file': '~/.ssh/id_rsa_be_vm'}]
            self.application = config.get('application')
            # ex. _________________________
            self.destination = config.get('destination')
            # ex. {'host_ip': '10.10.2.92', 'user':'root', 'identity_file': '~/.ssh/id_rsa_it_vm'}
            self.files = config.get('files', '')
            forwarders = config.get('forwarders')
            # ex. [{'local_port': 587, 'remote_port': 587}, {'local_port': 995, 'remote_port': 995}]
            self.forwarders_string = ' '.join([f'-L:{forwarder["local_port"]}:'
                                               # f'{self.destination["host_ip"]}:'
                                               f'{forwarder["remote_interface"]}:'
                                               f'{forwarder["remote_port"]}' for forwarder in
                                               forwarders]) if forwarders else ''
            self.forwarders_ports = ', '.join([str(forwarder["local_port"])
                                               for forwarder in forwarders]) if forwarders else ''
            self.all_hosts = [gateway["host_ip"] for gateway in self.gateways]
            self.all_hosts.append(self.destination["host_ip"])
            # ex. ['10.10.1.72', '10.10.2.92']
        except AttributeError as exp:
            self._logger.error('configuration file could not be parsed. %s', exp)  # raised by config.get()
            raise InvalidConfigurationFile
        except FileNotFoundError:  # open()
            self._logger.error('configuration file could not be opened ("FileNotFoundError")')
            raise InvalidConfigurationFile
        except IOError:  # open()
            self._logger.error('not enough permissions to open configuration file ("IOError")')
        except ValueError:  # json.loads()
            self._logger.error('JSON document could not be deserialized ("ValueError")')
            raise InvalidConfigurationFile
        except MultipleInvalid:  # Schema()
            self._logger.error('data structure (dict) validating failed ("MultipleInvalid")')
            raise InvalidConfigurationFile

    def get_config(self, filename):
        """Validates the data structure and parses the parameters in a dictionary."""
        with open(filename, 'r') as file:
            _temp = json.loads(file.read())
            _mode = MODE_SCHEMA(_temp)
            if _mode.get('mode') == 'TOR':
                # self._logger.info('mode TOR enabled')
                schema = TOR_SCHEMA(_temp)
            elif _mode.get('mode') == 'FOR':
                # self._logger.info('mode FOR enabled')
                schema = FOR_SCHEMA(_temp)
            elif _mode.get('mode') == 'INTERACTIVE':
                # self._logger.info('mode COMMAND enabled')
                schema = INTERACTIVE_SCHEMA(_temp)
            elif _mode.get('mode') == 'FILE':
                # self._logger.info('mode FILE enabled')
                schema = FILE_SCHEMA(_temp)
            else:
                self._logger.error('no mode enabled')
                schema = None
            return schema


def write_ssh_config_file(path_ssh_cfg_minitor, gateways, destination):
    """Writes the configuration file with ProxyJump directives for ssh.

    The IdentityFile cannot be given as a run-time parameter. Therefore,
    we resort to a directive in a config file

    Returns:
        bool: True on success, False otherwise.

    """
    # ex. [{'host_ip': '10.10.1.72', 'user': 'root', 'identity_file': '~/.ssh/id_rsa_be_vm'}]
    # ex. {'host_ip': '10.10.2.92', 'user':'root', 'identity_file': '~/.ssh/id_rsa_it_vm'}

    content = ''
    for gateway in gateways:
        content += f'Host {gateway["host_ip"]}\n' \
                   f'  HostName {gateway["host_ip"]}\n' \
                   f'  User {gateway["user"]} \n' \
                   f'  IdentitiesOnly yes \n' \
                   f'  IdentityFile {gateway["identity_file"]}\n\n'
    content += f'Host {destination["host_ip"]}\n' \
               f'  HostName {destination["host_ip"]}\n' \
               f'  User {destination["user"]} \n' \
               f'  IdentitiesOnly yes \n' \
               f'  IdentityFile {destination["identity_file"]}\n\n'
    LOGGER.debug('"%s" is written to ssh config config file: %s', content.replace("\n", ""),
                 path_ssh_cfg_minitor)
    try:
        with open(path_ssh_cfg_minitor, 'w') as data_source:
            data_source.write(content)
    except IOError:
        LOGGER.error('ssh config file %s could not be read', path_ssh_cfg_minitor)
        return False
    return True


class StateManager:  # context manager
    """Cleans up objects (eg. Tunnel, Assistant) when exiting.

    An KeyboardInterrupt, which is an exception, will first be caught
    by this class, or specifically, by __exit__(). Consequently, this method
    will invoke the _clean_up() to stop all instantiated objects.
    """

    def __init__(self):
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix='StateManager')
        self._logger = logging.getLogger(logger_name)
        self._running_instances = []

    def __enter__(self):
        self._logger.info('setting up tunneling...')
        return self

    def add_object(self, object_):
        """Collects instantiated Tunnel, instantiated Assistant and shape(s) for clean up purposes."""
        self._running_instances.append(object_)

    def _clean_up(self):
        for object_ in reversed(self._running_instances):
            self._logger.debug('cleaning up %s', str(object_))
            object_.stop()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._logger.info('terminating agent, assistant, and tunnel...')
        self._clean_up()
        self._logger.info('tunneling terminated')
        if exc_type is KeyboardInterrupt:
            self._logger.debug("KeyboardInterrupt caught")
            return True  # https://effbot.org/zone/python-with-statement.htm


class Heartbeat:  # context manager
    """Determines periodically the state of the tunnel."""

    def __init__(self, local_heartbeat_port):
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix='Heartbeat')
        self._logger = logging.getLogger(logger_name)
        self.thread = None
        self.is_tunnel_intact = True
        self.terminate = False
        self.local_heartbeat_port = local_heartbeat_port

    def _run_heartbeat(self):
        while self.thread.is_alive:
            if self.terminate:
                return None
            self.is_tunnel_intact = start_ping(self.local_heartbeat_port)
            if self.is_tunnel_intact:
                self._logger.debug('heartbeat signal was successfully returned')
            else:
                self._logger.error('heartbeat signal was not returned')
            sleep(HEARTBEAT_DURATION)

    def __enter__(self):
        self.thread = threading.Thread(target=self._run_heartbeat)
        self.thread.start()
        self._logger.info('heartbeat mechanism started')
        return self

    def __exit__(self, type_, value, traceback):
        self.terminate = True
        self._logger.info('heartbeat mechanism stopped')


def start_application(binary_name, binary_location):  # used in either FOR (w/ Thunderbird) or TOR mode (w/ Firefox)
    """Starts the application."""
    try:
        # process = subprocess.run([binary_location], capture_output=False)
        # process = subprocess.run([binary_location], subprocess.DEVNULL)
        # with open(os.devnull, 'w') as devnull:
        #     process = subprocess.run([binary_location], stdout=devnull, stderr=devnull)
        process = subprocess.Popen(binary_location, shell=True)
        # LOGGER.debug('application %s executed and the return code was: %s', binary_name, process.returncode)
        return process
    except FileNotFoundError:
        LOGGER.error('the executable binary %s of the application was not found', binary_name)
        return False


def start_ping(local_heartbeat_port):
    """Sends a HTTP GET request and processes the response."""
    local_heartbeat_port = local_heartbeat_port
    http_code = 0
    result = None
    try:
        with urllib.request.urlopen(f'http://localhost:{local_heartbeat_port}', timeout=2, data=None) as request_obj:
            http_code = request_obj.getcode()
    except (URLError, ConnectionResetError):
        LOGGER.debug('minitoragent did not respond to GET request. '
                     'probable cause: gateways or destination host unreachable, '
                     'localhost (client) has no connection to the Internet, or '
                     'the agent on destination host is not bind to local port.')
        result = False
    except timeout:  # this exception needed?
        LOGGER.debug('minitoragent did not respond to GET request in a timely fashion.'
                     'probable cause: gateways or destination host unreachable, '
                     'localhost (client) has no connection to the Internet, or '
                     'the agent on destination host is not bind to local port.')
        result = False
    if http_code == 200:
        result = True
    return result
