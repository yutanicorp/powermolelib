.. :changelog:

History
-------

0.0.1 (13-05-2020)
---------------------

* First code creation


0.1.0 (13-05-2020)
------------------

* first commit


0.1.1 (13-05-2020)
------------------

* pypi complains filename has been used, increment version


0.1.2 (15-05-2020)
------------------

* debug mode added + logger_basename given a correct name


1.0.0 (16-05-2020)
------------------

* tunnel.py is heavily refactored: 1) instead of assigning individual ports to the instance a dictionary is used, 2) a new method is created named periodically_purge_buffer() which should be called once from the cli + agentassistant.py is renamed to instructor.py


1.0.1 (16-05-2020)
------------------

* _run_purger() modified to include try block + text updated


2.0.0 (16-05-2020)
------------------

* Assistant() renamed to Instructor() and start() of transferagent modified (due to bugfix: the agent module could never be copied successfully)


2.0.1 (04-07-2020)
------------------

* scp versions released after 21 Apr 2020 breaks when using the ProxyJump directive. this error is shown during execution of powermole when user has a newer scp installed. at this moment no solution how to deal with this issue.


2.1.0 (04-07-2020)
------------------

* bug fixed: powermole crashed when using 1 intermediary host


2.2.0 (04-07-2020)
------------------

* bug fixed: program didn't work using >1 intermediary hosts


2.2.1 (31-10-2020)
------------------

* forwardering string enclosed with quotes (for IPv6), timeout for establishing SSH conn. increased to 10s, requirements updated for prospector


3.0.0 (26-03-2021)
------------------

* PLAIN mode added and COMMAND and TRANSFER (previously FILE) modes are turned into methods + Tunnel() and TransferAgent() are refactored to appened authenticated hosts to the instance variable authenticated_hosts.


3.0.1 (30-03-2021)
------------------

* _issue_command() in agent.py refactored: finally in try/except block added


3.0.2 (11-04-2021)
------------------

* SocketServer, DataProtocol and related components in instructor.py and agent.py completely refactored + created new Logging module


3.1.0 (26-04-2021)
------------------

* Refactor the code to make bootstrapping the Agent more robust


3.1.1 (17-05-2021)
------------------

* Refactor SOCKS proxy server code for readability


3.1.2 (17-05-2021)
------------------

* Change version of Python interpreter


3.2.0 (25-05-2021)
------------------

* Add parameter deploy path for the transfer agent logic, refactor (and fix) SOCKS proxy server code, rename (API) parameters, and add docstrings
