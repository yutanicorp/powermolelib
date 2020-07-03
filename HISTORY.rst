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
