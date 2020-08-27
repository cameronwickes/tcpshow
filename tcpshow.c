/*
 *
 *  This code is Copyright (C) 2020, Cameron Wickes.
 *  Permission is granted for code modification, but not granted
 *  for redistribution of modifications or modified code. License
 *  is granted for non-commercial use only.
 *
 *  This code reads in a libpcap compatible file and extracts 
 *  user specified fields and display them to the user, to help 
 *  them get a better understanding as to what values are inside 
 *  the packet. Libpcap 0.4 (or higher) is required.
 * 
 *  TODO: Implement ARP and IP6
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define VERSION "0.1"
#define STRINGFORMAT 64
#define TOTALOPTIONS 24
#define TCP_SYN 0x02
#define TCP_ACK 0x10
#define TCP_FIN 0x01
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

//Debugging and flag declarations
char sourceFile[512];
char optionBuffer[512];
char errorBuffer[4096];
char debugBuffer[4096];
int fileFlag, showFlag, outputFlag;
int debugFlag = 0;

//Protocol Dictionary declaration
char* protocolsDictionary[][2] = {{"0", "HOPOPT"},{"1", "ICMP"},{"2", "IGMP"},{"3", "GGP"},{"4", "IPv4"},{"5", "ST"},{"6", "TCP"},{"7", "CBT"},{"8", "EGP"},{"9", "IGP"},{"10", "BBN-RCC-MON"},{"11", "NVP-II"},{"12", "PUP"},{"13", "ARGUS"},{"14", "EMCON"},{"15", "XNET"},{"16", "CHAOS"},{"17", "UDP"},{"18", "MUX"},{"19", "DCN-MEAS"},{"20", "HMP"},{"21", "PRM"},{"22", "XNS-IDP"},{"23", "TRUNK-1"},{"24", "TRUNK-2"},{"25", "LEAF-1"},{"26", "LEAF-2"},{"27", "RDP"},{"28", "IRTP"},{"29", "ISO-TP4"},{"30", "NETBLT"},{"31", "MFE-NSP"},{"32", "MERIT-INP"},{"33", "DCCP"},{"34", "3PC"},{"35", "IDPR"},{"36", "XTP"},{"37", "DDP"},{"38", "IDPR-CMTP"},{"39", "TP++"},{"40", "IL"},{"41", "IPv6"},{"42", "SDRP"},{"43", "IPv6-Route"},{"44", "IPv6-Frag"},{"45", "IDRP"},{"46", "RSVP"},{"47", "GRE"},{"48", "DSR"},{"49", "BNA"},{"50", "ESP"},{"51", "AH"},{"52", "I-NLSP"},{"53", "SWIPE"},{"54", "NARP"},{"55", "MOBILE"},{"56", "TLSP"},{"57", "SKIP"},{"58", "IPv6-ICMP"},{"59", "IPv6-NoNxt"},{"60", "IPv6-Opts"},{"61", "any"},{"62", "CFTP"},{"63", "any"},{"64", "SAT-EXPAK"},{"65", "KRYPTOLAN"},{"66", "RVD"},{"67", "IPPC"},{"68", "any"},{"69", "SAT-MON"},{"70", "VISA"},{"71", "IPCV"},{"72", "CPNX"},{"73", "CPHB"},{"74", "WSN"},{"75", "PVP"},{"76", "BR-SAT-MON"},{"77", "SUN-ND"},{"78", "WB-MON"},{"79", "WB-EXPAK"},{"80", "ISO-IP"},{"81", "VMTP"},{"82", "SECURE-VMTP"},{"83", "VINES"},{"84", "TTP"},{"84", "IPTM"},{"85", "NSFNET-IGP"},{"86", "DGP"},{"87", "TCF"},{"88", "EIGRP"},{"89", "OSPFIGP"},{"90", "Sprite-RPC"},{"91", "LARP"},{"92", "MTP"},{"93", "AX.25"},{"94", "IPIP"},{"95", "MICP"},{"96", "SCC-SP"},{"97", "ETHERIP"},{"98", "ENCAP"},{"99", "any"},{"100", "GMTP"},{"101", "IFMP"},{"102", "PNNI"},{"103", "PIM"},{"104", "ARIS"},{"105", "SCPS"},{"106", "QNX"},{"107", "A/N"},{"108", "IPComp"},{"109", "SNP"},{"110", "Compaq-Peer"},{"111", "IPX-in-IP"},{"112", "VRRP"},{"113", "PGM"},{"114", "any"},{"115", "L2TP"},{"116", "DDX"},{"117", "IATP"},{"118", "STP"},{"119", "SRP"},{"120", "UTI"},{"121", "SMP"},{"122", "SM"},{"123", "PTP"},{"124", "ISIS"},{"125", "FIRE"},{"126", "CRTP"},{"127", "CRUDP"},{"128", "SSCOPMCE"},{"129", "IPLT"},{"130", "SPS"},{"131", "PIPE"},{"132", "SCTP"},{"133", "FC"},{"134", "RSVP-E2E-IGNORE"},{"135", "Mobility"},{"136", "UDPLite"},{"137", "MPLS-in-IP"},{"138", "manet"},{"139", "HIP"},{"140", "Shim6"},{"141", "WESP"},{"142", "ROHC"},{"143", "Ethernet"},{"144-252", "Unassigned"},{"253", "Use"},{"254", "Use"},{"255", "Reserved"}};

//Output array declarations
int optionsArray[TOTALOPTIONS];
char* outputArray[TOTALOPTIONS];
int optionsPointer = 0;
char* optionsDictionary[][3] = {
	{"srcmac","0","Source MAC"},
	{"dstmac","1","Destination MAC"},
	{"ethtype","2","Ether Type"},
	{"srcip","3","Source IP"},
	{"dstip","4","Destination IP"},
	{"iplen","5","IP Header Length"},
	{"ipid","6","IP ID"},
	{"frag","7","Fragment Bits"},
	{"ttl","8","TTL"},
	{"proto","9","Protocol"},
	{"ipchk","10","IP Checksum"},
	{"hdrlen","11","Proto Header Length"},
	{"srcprt","12","Source Port"},
	{"dstprt","13","Destination Port"},
	{"tcpseq","14","TCP Seq"},
	{"tcpack","15","TCP Ack"},
	{"tcpflg","16","TCP Flags"},
	{"tcpwin","17","TCP Window Size"},
	{"protochk","18","Protocol Checksum"},
	{"tcpurg","19", "TCP Urgent Pointer"},
	{"icmptype","20", "ICMP Type"},
	{"icmpcode","21", "ICMP Code"},
	{"tlen","22", "Total Length"},
	{"dlen","23", "Data Length"}};


//DEBUG outputs a debugging string while the debug flag is set.
void DEBUG(char *debuggingString)
{
  if(debugFlag) { 
  	printf("DEBUG: %s\n",debuggingString); 
  }
}

//USAGE prints relevant information on how to use the program.
void usage() {
	printf("Usage:\n\ttcpshow -r <source_file> -e <fields>\n\n");
	
	printf("\t-h\tThis help\n");
	printf("\t-r\tSpecify a source pcap file to read in.\n");
	printf("\t-c\tSpecify a certain number of packets to extract.\n");
	printf("\t-e\tSpecify an extracted field to show.\n\n");
	
	printf("\t\tsrcmac\tSource MAC Address.\n");
	printf("\t\tdstmac\tDestination MAC Address.\n");
	printf("\t\tethtype\tEthernet Type.\n");
	printf("\t\tsrcip\tSource IP Address.\n");
	printf("\t\tdstip\tDestination IP Address.\n");
	printf("\t\tiplen\tLength of the IP Header.\n");
	printf("\t\tipid\tIP Identification Number.\n");
	printf("\t\tfrag\tFragmentation Bytes.\n");
	printf("\t\tttl\tTime To Live.\n");
	printf("\t\tproto\tType of Protocol.\n");
	printf("\t\tipchk\tIP Header Checksum.\n");
	printf("\t\thdrlen\tLength of the Protocol Header.\n");	
	printf("\t\tsrcprt\tSource Port.\n");
	printf("\t\tdstprt\tDestination Port.\n");
	printf("\t\ttcpseq\tTCP Sequence Number.\n");
	printf("\t\ttcpack\tTCP Acknowledgement Number.\n");
	printf("\t\ttcpflg\tTCP Flags.\n");
	printf("\t\ttcpwin\tTCP Window Size.\n");
	printf("\t\ttcpurg\tTCP Urgent Pointer.\n");
	printf("\t\tprotochk\tProtocol Header Checksum.\n");
	printf("\t\ticmptype\tICMP Type.\n");
	printf("\t\ticmpcode\tICMP Code.\n");
 	printf("\t\ttlen\tTotal length of the packet (excluding frame).\n");
	printf("\t\tdlen\tLength of the data segment (tcp).\n");
 	exit(3);
}

//BUILDARRAY builds the array of options that the user wants to output
void buildArray(char* field) {
	int foundFlag = 0;
	for (int i = 0; i < TOTALOPTIONS; i++) {
		if (!(strcmp(field,optionsDictionary[i][0]))) {
			sprintf(debugBuffer,"Field Recognised: %s",field);
            DEBUG(debugBuffer);
			optionsArray[optionsPointer] = atoi(optionsDictionary[i][1]);
			sprintf(debugBuffer,"Index of field %s found (%d)",field,optionsArray[optionsPointer]);
			DEBUG(debugBuffer);
			optionsPointer ++;
			foundFlag = 1;
			break;
		}
	}
	if (!foundFlag) {
		printf("ERROR: Field '%s' not found. See -h for usage...\n",field);
		exit(3);
	}
	
}

//OUTPUTFIELDS outputs the specified fields to the terminal.
void outputFields(char* outputs[]) {
		char optionNumber[4];
		if (!outputFlag) {
			for (int i=0;i < optionsPointer; i++) {
				for (int j=0; j < TOTALOPTIONS; j++) {	
					sprintf(optionNumber,"%d",optionsArray[i]);
					if (!strcmp(optionNumber, optionsDictionary[j][1])) {
						printf("%-25s",optionsDictionary[j][2]);			
					}
				}
			}
			printf("\n");
			outputFlag = 1;
		}
		for (int i=0; i < optionsPointer; i++) {
			printf("%-25s",outputs[optionsArray[i]]);
		} 
		printf("\n");
}


//PACKETANALYSIS extracts the fields out of the packet and places them into the options array
void packetAnalysis(unsigned char *userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	const struct udphdr* udpHeader;
	const struct icmphdr* icmpHeader;
	char* outputs[TOTALOPTIONS];
	unsigned char *data;
	char sourceIP[STRINGFORMAT] = "-", destinationIP[STRINGFORMAT] = "-", sourcePort[STRINGFORMAT] = "-", destinationPort[STRINGFORMAT] = "-", totalLength[STRINGFORMAT] = "-", ipHeaderLength[STRINGFORMAT] = "-", protoHeaderLength[STRINGFORMAT] = "-", dataLength[STRINGFORMAT] = "-", sourceMAC[STRINGFORMAT] = "-",destinationMAC[STRINGFORMAT] = "-", etherType[STRINGFORMAT] = "-", ipID[STRINGFORMAT] = "-", fragmentBytes[STRINGFORMAT] = "-", timeToLive[STRINGFORMAT] = "-", protocol[STRINGFORMAT] = "-", ipChecksum[STRINGFORMAT] = "-", protocolHeaderLength[STRINGFORMAT] = "-", tcpSequenceNumber[STRINGFORMAT] = "-", tcpAcknowledgementNumber[STRINGFORMAT] = "-", tcpFlags[STRINGFORMAT] = "-", tcpWindowSize[STRINGFORMAT] = "-", protocolChecksum[STRINGFORMAT] = "-", tcpUrgentPointer[STRINGFORMAT] = "-", icmpType[STRINGFORMAT] = "-", icmpCode[STRINGFORMAT] = "-", icmpIdentifier[STRINGFORMAT] = "-";
 
 	ethernetHeader = (struct ether_header*)packet;
 	sprintf(sourceMAC, "%02x:%02x:%02x:%02x:%02x:%02x", (ethernetHeader->ether_shost[0]), (ethernetHeader->ether_shost[1]), (ethernetHeader->ether_shost[2]), (ethernetHeader->ether_shost[3]),(ethernetHeader->ether_shost[4]), (ethernetHeader->ether_shost[5]));
 	sprintf(destinationMAC, "%02x:%02x:%02x:%02x:%02x:%02x",(ethernetHeader->ether_dhost[0]), (ethernetHeader->ether_dhost[1]), (ethernetHeader->ether_dhost[2]), (ethernetHeader->ether_dhost[3]), (ethernetHeader->ether_dhost[4]), (ethernetHeader->ether_dhost[5]));
 	sprintf(etherType,"%#04x",ntohs(ethernetHeader->ether_type));

 	//IP
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
 	   	inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
 	   	inet_ntop(AF_INET, &(ipHeader->ip_dst), destinationIP, INET_ADDRSTRLEN);
		sprintf(ipID,"%d",ntohs(ipHeader->ip_id));
		sprintf(timeToLive,"%d",ipHeader->ip_ttl);
		sprintf(ipHeaderLength,"%d",(ipHeader->ip_hl) << 2);
		sprintf(totalLength,"%d",ntohs(ipHeader->ip_len));
		sprintf(ipChecksum,"%#04x",ntohs(ipHeader->ip_sum));
		
		char fragmentBuffer[STRINGFORMAT];
		char fragmentOffset[STRINGFORMAT];
		strcpy(fragmentBuffer,"");
		if ((ntohs(ipHeader->ip_off) & IP_RF) == IP_RF) { strncat(fragmentBuffer,"RF, ",5); } 
		if ((ntohs(ipHeader->ip_off) & IP_DF) == IP_DF) { strncat(fragmentBuffer,"DF, ",5); }
		if ((ntohs(ipHeader->ip_off) & IP_MF) == IP_MF) { strncat(fragmentBuffer,"MF, ",5); }
		sprintf(fragmentOffset,"Offset: %d",((ntohs(ipHeader->ip_off) & IP_OFFMASK)*8));
		strncat(fragmentBuffer,fragmentOffset,strlen(fragmentOffset));
		sprintf(fragmentBytes,"0x%04x (%s)",ntohs(ipHeader->ip_off),fragmentBuffer);

		for (int i=0; i < 149; i++) {
			if (atoi(protocolsDictionary[i][0]) == ipHeader->ip_p) {
				sprintf(protocol,"%d (%s)",ipHeader->ip_p,protocolsDictionary[i][1]);
				break;
			}
		}

		//TCP
    	if (ipHeader->ip_p == 6) {
        	tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
      	 	sprintf(sourcePort,"%d",ntohs(tcpHeader->source));
      	 	sprintf(destinationPort,"%d",ntohs(tcpHeader->dest));
      	 	sprintf(protocolHeaderLength,"%d",(tcpHeader->th_off * 4));
      	 	sprintf(tcpSequenceNumber,"%d",ntohl(tcpHeader->th_seq));
      	 	sprintf(tcpAcknowledgementNumber,"%d",ntohl(tcpHeader->th_ack));
      	 	sprintf(tcpWindowSize,"%d",ntohs(tcpHeader->th_win));
      	 	sprintf(protocolChecksum,"%#04x",ntohs(tcpHeader->th_sum));
      	 	sprintf(tcpUrgentPointer,"%d",ntohs(tcpHeader->th_urp));

            char tcpFlagBuffer[STRINGFORMAT];
			strcpy(tcpFlagBuffer,"");
			if (((tcpHeader->th_flags) & TCP_SYN) == TCP_SYN) { strncat(tcpFlagBuffer,"S",2); }
			if (((tcpHeader->th_flags) & TCP_FIN) == TCP_FIN) { strncat(tcpFlagBuffer,"F",2); } 
			if (((tcpHeader->th_flags) & TCP_RST) == TCP_RST) { strncat(tcpFlagBuffer,"R",2); } 
			if (((tcpHeader->th_flags) & TCP_PSH) == TCP_PSH) { strncat(tcpFlagBuffer,"P",2); } 			 
			if (((tcpHeader->th_flags) & TCP_ACK) == TCP_ACK) { strncat(tcpFlagBuffer,".",2); }
			if (((tcpHeader->th_flags) & TCP_URG) == TCP_URG) { strncat(tcpFlagBuffer,"U",2); } 
			if (((tcpHeader->th_flags) & TCP_ECE) == TCP_ECE) { strncat(tcpFlagBuffer,"E",2); } 			
			if (((tcpHeader->th_flags) & TCP_CWR) == TCP_CWR) { strncat(tcpFlagBuffer,"C",2); }  
			sprintf(tcpFlags, "0x%02x [%s]", (tcpHeader->th_flags),tcpFlagBuffer);
         }
         
         //UDP
         if (ipHeader->ip_p == 17) {
			udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sprintf(protocolHeaderLength,"%d",8);
			sprintf(sourcePort,"%d",ntohs(udpHeader->source));
      	 	sprintf(destinationPort,"%d",ntohs(udpHeader->dest));
      	 	sprintf(protocolChecksum,"%#04x",ntohs(udpHeader->uh_sum));
         }

         //ICMP
         if (ipHeader->ip_p == 1) {		
         	icmpHeader = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sprintf(protocolHeaderLength,"%d",8);
			sprintf(icmpCode, "%d", ntohs(icmpHeader->code));
			sprintf(icmpType, "%d", ntohs(icmpHeader->type));
			sprintf(protocolChecksum, "%#04x", ntohs(icmpHeader->checksum));
         }
                
        sprintf(dataLength,"%d",(atoi(totalLength) - atoi(ipHeaderLength) - atoi(protocolHeaderLength)));
         
		outputs[0] = sourceMAC;
      	outputs[1] = destinationMAC;
        outputs[2] = etherType;
        outputs[3] = sourceIP;
        outputs[4] = destinationIP;
        outputs[5] = ipHeaderLength;
        outputs[6] = ipID;
        outputs[7] = fragmentBytes;
        outputs[8] = timeToLive;
        outputs[9] = protocol;
        outputs[10] = ipChecksum;
        outputs[11] = protocolHeaderLength;
        outputs[12] = sourcePort;
        outputs[13] = destinationPort;
        outputs[14] = tcpSequenceNumber;
        outputs[15] = tcpAcknowledgementNumber;
        outputs[16] = tcpFlags;
        outputs[17] = tcpWindowSize;
        outputs[18] = protocolChecksum;
        outputs[19] = tcpUrgentPointer;
		outputs[20] = icmpType;
		outputs[21] = icmpCode;
        outputs[22] = totalLength;
        outputs[23] = dataLength;
       	outputFields(outputs);
	}
} 



//MAIN handles command line arguments and errors.
int main(int argc, char **argv) {
   char option;   
   int packetCount = 0;
   pcap_t *pcapDescriptor;
   strcpy(sourceFile, ""); 
   
   for(option = getopt(argc, argv, "r:e:c:h");
      option != -1;
      option = getopt(argc, argv, "r:e:c:h"))
    {
      switch(option)
	{
         case 'r': 
            strncpy(sourceFile, optarg, 511);
            sprintf(debugBuffer,"File Provided: %s",sourceFile);
            DEBUG(debugBuffer);
            fileFlag = 1;
            break;
         case 'e':
         	strncpy(optionBuffer, optarg, 511);
         	sprintf(debugBuffer,"Field Provided: %s",optionBuffer);
            DEBUG(debugBuffer);
            buildArray(optionBuffer);
         	showFlag = 1;
         	break;
         case 'c':
         	if (atoi(optarg) != 0) {
         		packetCount = atoi(optarg);
         	} else {
         		printf("ERROR: Option (-c) needs an integer value...\n");
         		exit(3);
         	}
         	break;
         case 'h':
         	usage();
         	break;
         case ':':
            printf("ERROR: Option (%c) provided without a value...\n",optopt);
            break;
         case '?':
            printf("ERROR: Unknown option (%c) provided. See -h for usage...\n", optopt);
            break;
      }
   }
   
   for(; optind < argc; optind++){
        strncpy(optionBuffer, argv[optind], 511);
		sprintf(debugBuffer,"Field Provided: %s",optionBuffer);
        DEBUG(debugBuffer);
        buildArray(optionBuffer);
   }
   
    if (!(fileFlag && showFlag)) { usage(); }
    
    pcapDescriptor = pcap_open_offline(sourceFile,errorBuffer);
    if (pcapDescriptor == NULL) {
    	printf("ERROR: Could not open the source file specified...\n");
    	exit(3);
    }
	if (pcap_loop(pcapDescriptor,packetCount,packetAnalysis,NULL) < 0) {
		printf("ERROR: Packet processing failed. Check you provided a valid pcap file...\n");
		exit(3);
	}

	sprintf(debugBuffer,"Packet processing of %s completed successfully.",sourceFile);
	DEBUG(debugBuffer);
	
	return 0;
}
