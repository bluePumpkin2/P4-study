/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>             version;
    bit<4>             ihl;
    bit<8>             diffserv;
    bit<16>            totalLen;
    bit<16>            identification;
    bit<3>             flags;
    bit<13>            fragOffset;
    bit<8>             ttl;
    bit<8>             protocol;
    bit<16>            hdrChecksum;
    ip4Addr_t          srcAddr;
    ip4Addr_t          dstAddr;
}

header icmp_t{
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> identification;
    bit<16> seqNo;
}

header tcp_t {
    //20バイト　ここまで共通ヘッダ
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header remaining_header_t {
    //urgentPtr以降のTCPヘッダ。タイムスタンプなど
    varbit<320>      remaining_header;
}

header payload_t {
    bit<8>          rewrite;
    varbit<12112>   data;
}

struct metadata {
    bit<16> calculated_tcp_len;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t              ipv4;
    icmp_t              icmp;
    tcp_t               tcp;
    remaining_header_t  rheader;
    payload_t           payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
	packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            1:          parse_icmp;
            6:          parse_tcp;
            default:    accept;
        }
    }

    state parse_icmp{
        packet.extract(hdr.icmp);
        transition accept;
    }
    
    state parse_tcp{
        packet.extract(hdr.tcp);
        transition parse_rheader;
    }

    state parse_rheader{
        //残りのTCPヘッダの長さを計算　既キャプチャヘッダは20バイト
        bit<16> rheader_bytes = (bit<16>)(hdr.tcp.dataOffset) * 4 - 20;
        bit<32> rheader_extract_size = (bit<32>)(rheader_bytes) * 8;
        packet.extract(hdr.rheader, rheader_extract_size);
        transition parse_payload;
    }
    
    state parse_payload{
        // IPv4ヘッダを16ビット幅にキャスト
        bit<16> ipv4_ihl_bytes = (bit<16>)(hdr.ipv4.ihl) * 4;
        // TCPヘッダを16ビット幅にキャスト
        bit<16> tcp_hdr_bytes = (bit<16>)(hdr.tcp.dataOffset) * 4;
        // ペイロードの長さを計算　マイナスはペイロードの一部としてのrewrite分
        bit<32> payload_extract_size = ((bit<32>)(hdr.ipv4.totalLen - ipv4_ihl_bytes - tcp_hdr_bytes)) * 8 - 8;

        packet.extract(hdr.payload, payload_extract_size);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
	    }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { 
        if(hdr.ipv4.isValid()){
            if(hdr.payload.isValid()){
                hdr.ipv4.diffserv = 5;
                
                //最初のいくつかのパケットはペイロードを書き換えてはいけないものがあるので、
                //書き換えても良い1024byte以上のパケットのみを書き換える
                if(hdr.ipv4.totalLen > 1024){
                    hdr.tcp.res = 3;                //TCPヘッダの書き換え
                    hdr.payload.rewrite = 255;      //ペイロードの書き換え
                    hdr.tcp.checksum = 0;
                }
            }
        }

        // IPv4ヘッダ長さ（hdr.ipv4.ihl）を16ビット幅にキャスト
        bit<16> ipv4_ihl_bytes = (bit<16>)(hdr.ipv4.ihl) * 4;

        // TCPセグメントの長さを計算し、メタデータに格納
        meta.calculated_tcp_len = hdr.ipv4.totalLen - ipv4_ihl_bytes;
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);


        // TCPヘッダとペイロードのチェックサム再計算
        update_checksum(    
            hdr.payload.isValid(),       // payloadが有効な場合にのみ計算
            { hdr.ipv4.srcAddr,          // Pseudo-header: Source IP Address
              hdr.ipv4.dstAddr,          // Pseudo-header: Destination IP Address
              (bit<8>)0,                 // Pseudo-header: Reserved (zero)
              hdr.ipv4.protocol,         // Pseudo-header: Protocol (TCP)
              meta.calculated_tcp_len,   // Pseudo-header: TCP Length
              hdr.tcp.srcPort,           // TCP: Source Port
              hdr.tcp.dstPort,           // TCP: Destination Port
              hdr.tcp.seqNo,             // TCP: Sequence Number
              hdr.tcp.ackNo,             // TCP: Acknowledgment Number
              hdr.tcp.dataOffset,        // TCP: Data Offset and Reserved
              hdr.tcp.res,
              hdr.tcp.ctrl,              // TCP: Flags
              hdr.tcp.window,            // TCP: Window Size
              hdr.tcp.urgentPtr,         // TCP: Urgent Pointer
              hdr.rheader.remaining_header,
              hdr.payload.rewrite,
              hdr.payload.data
            },         
            hdr.tcp.checksum,
            HashAlgorithm.csum16);       
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	    packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.rheader);
        packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
