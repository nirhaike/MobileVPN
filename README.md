# MobileVPN #
A simple and flexible VPN server program written in python.
This program routes all internet traffic of connected devices. It supports an unlimited amount of connections at a specific time. and contains a web interface for handling the server.

The client software is currently written only for the Android operating system.

## Features ##
1. Route all IP-layer traffic through the VPN Server.
2. Encrypted and Compressed sessions.
3. View which applications are using the internet.
4. Modular code with comments, which makes the server flexible for adding more features.
5. Download the traffic in .pcap format.

## Requirements ##
1. Windows Machine (The server was not tested on mac/linux)
2. Pycrypto module for python
3. Scapy module (This depencency may be removed in a future update)
