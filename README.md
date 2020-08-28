
# tcpshow

>This code reads in a libpcap compatible file and extracts user specified fields to display them to the user. It aims to help analysts get a better understanding as to what values are inside the packet, to potentially identify anomalies.<br/>

<b>Libpcap 0.4 (or higher) is required.</b>

## Installation

### Clone

- Clone this repo to your local machine using `https://github.com/cameronwickes/tcpshow`.
	```
	$ git clone https://github.com/cameronwickes/tcpshow
	```

### Setup

- Compile and install the binary using make.

	```
	$ make
	$ sudo make install
	```

## Usage
```
$ tcpshow -r <source_file> -e <fields> [-c <count>]
```
<br/>

|Field|Description||Field|Description
|--|--|--|--|--|
|srcmac|Source MAC Address.||dstmac|Destination MAC Address.|
|ethtype|Ethernet Type.||srcip|Source IP Address.|
|dstip|Destination IP Address.||iplen|Length of the IP Header.|
|ipid|IP Identification Number.||frag|Fragmentation Bytes.|
|ttl|Time To Live.||proto|Protocol Type.|
|ipchk|IP Header Checksum||hdrlen|Length of the Protocol Header.|
|srcprt|Source Port.||dstprt|Destination Port.|
|tcpseq|TCP Sequence Number.||tcpack|TCP Acknowledgement Number.|
|tcpflg|TCP Flags.||tcpwin|TCP Window Size.|
|tcpurg|TCP Urgent Pointer.||protochk|Protocol Header Checksum.|
|icmptype|ICMP Type.||icmpcode|ICMP Code.|
|tlen|Total Length of the Packet (excl.frame)||dlen|Length of the Data Segment.|


## Support
Reach out to me through one of the following!

- Website at <a href="https://cameronwickes.com" target="_blank">`www.cameronwickes.com`</a>
- Twitter at <a href="https://twitter.com/cameronjwickes" target="_blank">`@cameronjwickes`</a>
- LinkedIn at <a href="https://www.linkedin.com/in/cameron-wickes-7b32aa192" target="_blank">`cameron-wickes`</a>
