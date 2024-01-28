.. :changelog:

History
-------

0.0.1 (13-05-2020)
---------------------

* First code creation


0.1.0 (13-05-2020)
------------------

* First commit


0.1.1 (13-05-2020)
------------------

* <None>


0.1.2 (15-05-2020)
------------------

* Add debug mode, refactor logging


1.0.0 (16-05-2020)
------------------

* Add parameter in tunnel.py to accept group of ports


1.0.1 (16-05-2020)
------------------

* Add method to periodically purge buffer


2.0.0 (16-05-2020)
------------------

* Refactor class responsible for instructing the Agent, refactor method responsible for transferring the Agent


2.0.1 (04-07-2020)
------------------

* <None>


2.1.0 (04-07-2020)
------------------

* Fix bug to make program work with 1 intermediary hosts


2.2.0 (04-07-2020)
------------------

* Fix bug to make program work with >1 intermediary hosts


2.2.1 (31-10-2020)
------------------

* Fix bug to work with IPv6 addresses on macOS, add higher timeout for establishing SSH connections, bump dependency


3.0.0 (26-03-2021)
------------------

* Add PLAIN mode, add COMMAND and TRANSFER options, add code to collect authenticated hosts


3.0.1 (30-03-2021)
------------------

* Refactor method responsible for sending commands


3.0.2 (11-04-2021)
------------------

* Refactor socket server and data protocol code, add new module


3.1.0 (26-04-2021)
------------------

* Refactor bootstrapagent.py to make robust


3.1.1 (17-05-2021)
------------------

* Refactor SOCKS code for readability


3.1.2 (17-05-2021)
------------------

* Add support for Python interpreter >3.7


3.2.0 (25-05-2021)
------------------

* Add parameter in transferagent.py, refactor and fix SOCKS code, refactor (API) parameters, add docstrings


3.3.0 (01-06-2021)
------------------

* Add feature to set heartbeat interval, refactor SOCKS code


3.3.1 (06-06-2021)
------------------

* Fix bug to avoid crashing when unable to connect, reword paragraph in README, reword commit messages in HISTORY.RST, reword list of keywords for PyPi


3.3.2 (02-12-2021)
------------------

* Fix bug responsible for crashing powermole during transfer Agent


3.4.0 (19-12-2021)
------------------

* Refactor heartbeat code and JSON validation schemas


3.4.1 (19-12-2021)
------------------

* Fix error handling when sending of files fails


3.4.2 (26-12-2021)
------------------

* Reword email address and fix sending files containing spaces


3.4.3 (28-12-2022)
------------------

* Fix security vulnerability in 3rd party package


3.4.4 (19-02-2023)
------------------

* Fix development workflow


3.4.5 (30-03-2023)
------------------

* Fix security vulnerability, add Python version check


3.4.6 (14-06-2023)
------------------

* Document paragraph about terminology


3.4.7 (27-08-2023)
------------------

* Add Read The Docs configuration file v2, Bump dependencies


3.4.8 (28-01-2024)
------------------

* Bump 3rd party package to fix security vulnerability, update template with newer Python version
