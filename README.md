# ping_sweeper.py

## Synposis
Ping one or more IPs.

## Description
Simple ping sweeper tool using scapy. 

Allows you to use an IP, range of IPs, cidr range, or all at the same time. 

## Dependencies
ping_sweeper.py requires the following dependencies:
- [scapy](https://pypi.org/project/scapy/)
  - `pip install scapy`
- [ansicolors](https://pypi.org/project/ansicolors/)
  - `pip install ansicolors`

## Usage

**Parameter --cidr, -c**
- type : str
- valid cidr range

**Parameter -ip**
- type : str
- one or more IPs in csv format
- range of IPs; must specifiy range in the last octet only

**Parameter -src**
- type : str
- set the src IP of the ping packet
- default value is your machine's IP
- allows you to spoof the IP in the packet, but then the response will never be returned to your machine.

**Parameter --verbose, -v**
- type : boolean
- print verbose output

<br/>
<br/>

**Example 1**

`py ping_sweeper.py -c "192.168.1.0/24"`

- Ping every IP within cidr range

**Example 2**

`py ping_sweeper.py -ip "192.168.1.100"`

- Ping one IP

**Example 3**

`py ping_sweeper.py -ip "192.168.1.100, 192.168.1.6"`

- Ping two IPs

**Example 4**

`py ping_sweeper.py -ip "192.168.1.1-20"`

- Ping a range of IPs

**Example 5**

`py ping_sweeper.py -ip "192.168.1.100, 192.168.1.6, 192.168.1.1-20"`

- Ping two IPS and a range of IPs

**Example 6**

`py ping_sweeper.py -c "192.168.3.0/24" -ip "192.168.1.100, 192.168.1.6, 192.168.1.1-20"`

- Ping a cidr range, two IPs, and a range of IPs
