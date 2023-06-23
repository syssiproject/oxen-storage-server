# Storage server testnet test suite

This directory contains a Python/pytest-based test repository to perform tests against the live Sispop
testnet.

Usage:

- install the [https://ci.sispop.rocks/sispop-io/sispop-pysispopmq](sispopmq Python module).  You can build it
  from source, or alternatively grab the python3-sispopmq deb package from our deb repo
  (https://deb.sispop.io)u.

- Run `py.test-3` to run the test suite.  (You likely need to install python3-pytest and
  python3-nacl, if not already installed).
