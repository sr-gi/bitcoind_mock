# Installation

Download / clone the repository and add it as a Python repository by:

- Placing it under the Python's lib folder (by default under `/usr/lib/python3.X/` for Linux systems and 
`/Library/Python/3.X/site-packages/` for OS X). (e.g `mv bitcoind_mock/bitcoind_mock /usr/lib/python3.X/`) where `X` is 
the subversion of Python3 installed in your system.

or

- Including the library folder path in the Python's path by running 
`PYTHONPATH=$PYTHONPATH:path_to_the_code/bitcoind_mock`.

or

- Using the library as a `PyCharm project`.

Copy / rename `sample_conf.py` to `conf.py` and configure it using your own data (or leave it with the defaults).

Install all the dependencies (check the [dependencies section](DEPENDENCIES.md)).