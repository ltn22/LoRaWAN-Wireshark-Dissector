# LoRaWAN Wireshark dissector

## Brief

This plugin is a LoRaWAN dissector for Wireshark.
It is current developed with LoRaWAN1.0.1 as a target.
These instructions were written by Quentin Lampin at Orange Labs.

## Installation

** This plugin requires to rebuild Wireshark from source code**

- Get a copy of Wireshark source code[here](https://github.com/wireshark/wireshark)
- Copy/paste the `lorawan` directory located in the `plugins` directory of this repository to the `plugins` directory of Wireshark
- Follow the instructions of the section 3. of `wireshark/doc/README.plugins`.
    Depending on your build tools (cmake, autotools, etc.), this requires changing a few files of Wiresharks, e.g. `CMakeLists.txt` for cmake, `Makefile.am` and `configure.ac` for autotools, etc.


## License

This dissector is distributed under the terms of the License GPLv2+: GNU GPL version 2 to comply with the licensing terms of Wireshark.

