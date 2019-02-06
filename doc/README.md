Thincoin Core
=============

Setup
---------------------
Thincoin Core is the original Thincoin client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Thincoin transactions (which is currently more than 7 GBs); depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Thincoin Core, visit [thincoin.org](https://thincoin.org).

Running
---------------------
The following are some helpful notes on how to run Thincoin on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/thincoin-qt` (GUI) or
- `bin/thincoind` (headless)

### Windows

Unpack the files into a directory, and then run thincoin-qt.exe.

### OS X

Drag Thincoin-Core to your applications folder, and then run Thincoin-Core.

### Need Help?

* See the documentation at the [Thincoin Wiki](https://thincoin.info/)
for help and more information.
* Ask for help on [#thincoin](http://webchat.freenode.net?channels=thincoin) on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net?channels=thincoin).
* Ask for help on the [ThincoinTalk](https://thincointalk.io/) forums.

Building
---------------------
The following are developer notes on how to build Thincoin on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [OS X Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The Thincoin repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Travis CI](travis-ci.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* Discuss on the [ThincoinTalk](https://thincointalk.io/) forums.
* Discuss general Thincoin development on #thincoin-dev on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net/?channels=thincoin-dev).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
