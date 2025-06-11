/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//IPv4のプロトコルタイプは0800
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

//各アドレス
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//おまじない******************************
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

#define IS_RESUBMITTED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT)
#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
#define IS_REPLICATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION)
//おまじない終了***************************

//クローンセッションIDの定義
//const bit<32> I2E_CLONE_SESSION_ID = 5;
//const bit<32> E2E_CLONE_SESSION_ID = 11;
const bit<32> RETURN_CLONE_SESSION_ID = 3;

//カウンターレジスタのための定義
#define PACKET_COUNT_WIDTH 32
typedef bit<PACKET_COUNT_WIDTH> PacketCount_t;
const bit<32> NUM_REGISTER = 65536;

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
    varbit<320>      remaining_header;
}

header payload_t {
    bit<32>         deq_timedelta;
    bit<8>          sep1;
    bit<24>         enq_qdepth;
    bit<8>          sep2;
    bit<24>         deq_qdepth;
    bit<8>          sep3;
    bit<8>          qid;
    bit<8>          sep4;
    bit<32>         ackNo_reg;
    bit<8>          sep5;
    bit<32>         counter;
    bit<8>          sep6;
    varbit<12112>   data;
}

struct metadata {
    @field_list(0)
    bit<16> calculated_tcp_len;
}

struct headers {
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    icmp_t              icmp;
    tcp_t               tcp;
    //remaining_header_t  rheader;
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
        transition parse_payload;
    }

    /*
    state parse_rheader{
        //残りのTCPヘッダの長さを計算　既キャプチャヘッダは20バイト
        bit<16> rheader_bytes = (bit<16>)(hdr.tcp.dataOffset) * 4 - 20;
        bit<32> rheader_extract_size = (bit<32>)(rheader_bytes) * 8;
        packet.extract(hdr.rheader, rheader_extract_size);
        transition parse_payload;
    }
    */
    
    state parse_payload{
        // IPv4ヘッダを16ビット幅にキャスト
        bit<16> ipv4_ihl_bytes = (bit<16>)(hdr.ipv4.ihl) * 4;
        // TCPヘッダを16ビット幅にキャスト
        bit<16> tcp_hdr_bytes = (bit<16>)(hdr.tcp.dataOffset) * 4;
        // ペイロードの長さを計算　マイナスはペイロードの一部としてのrewrite分
        bit<32> payload_extract_size = ((bit<32>)(hdr.ipv4.totalLen - ipv4_ihl_bytes - tcp_hdr_bytes)) * 8 - 200;

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

    //drop()でパケットドロップ
    action drop() {
        mark_to_drop(standard_metadata);
    }

    //通常のipv4パケットフォワーディング（出力スイッチポート設定, イーサネットアドレス変換, TTLデクリメント）
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    //静的テーブル：IPv4のdstAddrを最長一致で探索し、出力スイッチポートを割り当てる
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

    //カウンターレジスタの宣言：register<index長>(レジスタの個数) レジスタ名
    //P4のレジスタは配列のように捉えると分かりやすい：PacketCount_t pkt_counter[NUM_REGISTER] <- int array[10]
    register<PacketCount_t>(NUM_REGISTER) pkt_counter;

    apply {
        if(hdr.ipv4.isValid()){
            //静的テーブルを有効化
            ipv4_lpm.apply();

            //パケットカウント処理
            PacketCount_t tmp = 0;
            bit<32> index = (bit<32>)0;
            hash(index, HashAlgorithm.crc16, (bit<32>)0, {  hdr.ipv4.srcAddr, 
                                                            hdr.ipv4.dstAddr,
                                                            hdr.tcp.srcPort,
                                                            hdr.tcp.dstPort  }, NUM_REGISTER);
            
            //bit<32> index = (bit<32>)hdr.ipv4.protocol;
            @atomic{
                pkt_counter.read(tmp, index);
                tmp = tmp + 1;
                //hdr.payload.counter = tmp;
                pkt_counter.write(index, tmp);
            }

            //クローン処理
            //iperf3の途中から、数パケット毎にクローンする。
            //h1からの1024byte以上のパケットの場合にクローンする。
            if(tmp > 150000 && (bit<12>)tmp == 0 && hdr.ipv4.totalLen > 1024 && hdr.ipv4.dstAddr == 0x0a000505){
                clone_preserving_field_list(CloneType.I2E, RETURN_CLONE_SESSION_ID, 0);
            }
	    }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    //ackNoや広告ウィンドウサイズを記録するためのレジスタの宣言
    //index: 0 = ackNo, 1 = h2の広告ウィンドウサイズ, 2 = h5の広告ウィンドウサイズ, 3 = h6の広告ウィンドウサイズ
    register<PacketCount_t>(5) ackNo_reg;

    apply { 
        if(hdr.ipv4.isValid()){

            //Ingressでクローンしたパケットの場合
            //h1からのデータパケットをクローンする
            if(IS_I2E_CLONE(standard_metadata)){
                hdr.ipv4.diffserv = 0x0a;   //目印用

                //TCPセグメント計算
                bit<16> ipv4_ihl_bytes = (bit<16>)(hdr.ipv4.ihl) * 4;
                bit<16> tcp_hdr_bytes = (bit<16>)(hdr.tcp.dataOffset) * 4;
                bit<32> tcp_segment = ((bit<32>)(hdr.ipv4.totalLen - ipv4_ihl_bytes - tcp_hdr_bytes));
                
                //seqNoをackNoの値にし、seqNo + TCPセグメントをackNoにする
                bit<32> temp32 = hdr.tcp.ackNo;
                hdr.tcp.ackNo = hdr.tcp.seqNo + tcp_segment;
                hdr.tcp.seqNo = temp32;

                //ipv4のsrcAddrとdstAddrを入れ替える
                temp32 = hdr.ipv4.srcAddr;
                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                hdr.ipv4.dstAddr = temp32;

                //tcpのsrcPortとdstPortを入れ替える
                bit<16> temp16 = hdr.tcp.srcPort;
                hdr.tcp.srcPort = hdr.tcp.dstPort;
                hdr.tcp.dstPort = temp16;

                //TTLをデクリメントし、ACKフラグを立てる
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                hdr.tcp.ctrl = 0b000010000;

                //ethernetのdstAddrをsrcAddrにし、srcAddrはスイッチのh2側のポートのMACアドレスとする
                hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                if(hdr.ipv4.srcAddr == 0x0a000202){
                    hdr.ethernet.srcAddr = 0x080000000200;
                }else if(hdr.ipv4.srcAddr == 0x0a000505){
                    hdr.ethernet.srcAddr = 0x080000000500;
                }else if(hdr.ipv4.srcAddr == 0x0a000606){
                    hdr.ethernet.srcAddr = 0x080000000600;
                }
                
                //ペイロードを無効化し、通常のACKパケットと同様にペイロードを0byteにする
                //それに合わせて、ipv4のtotalLenを適切な値に書き換える
                hdr.payload.setInvalid();
                hdr.ipv4.totalLen = 0x0028;

                //通常のACKパケットの広告ウィンドウサイズを記録しているレジスタから読み取り、
                //クローンパケットのtcp.windowを書き換える
                @atomic{
                    //ackNo_reg.write(0, hdr.tcp.ackNo);
                    if(hdr.ipv4.srcAddr == 0x0a000202){
                        bit<32> current_window = 0;
                        ackNo_reg.read(current_window, 1);
                        hdr.tcp.window = (bit<16>)current_window;
                    }else if(hdr.ipv4.srcAddr == 0x0a000505){
                        bit<32> current_window = 0;
                        ackNo_reg.read(current_window, 2);
                        hdr.tcp.window = (bit<16>)current_window;
                    }else if(hdr.ipv4.srcAddr == 0x0a0606){
                        bit<32> current_window = 0;
                        ackNo_reg.read(current_window, 3);
                        hdr.tcp.window = (bit<16>)current_window;
                    }
                }
                
            //Egressでクローンしたパケットの場合
            //今回はEgressでのクローン処理はないので、目印のみ
            }else if(IS_E2E_CLONE(standard_metadata)){
                hdr.ipv4.diffserv = 0x0b;   //目印用

            //クローンされたパケット以外の場合    
            }else{
                hdr.ipv4.diffserv = 0x0c;   //目印用
                
                //クローンして作成したACKパケットと同等の通常のACKパケットをドロップする処理
                /*
                bit<32> drop_ack = 0;
                @atomic{
                    ackNo_reg.read(drop_ack, 0);
                    if(drop_ack == 0){
                        drop_ack = 10000;
                    }
                    if(hdr.tcp.ackNo == drop_ack){
                        mark_to_drop(standard_metadata);
                    }
                }
                */

                //通常のACKパケットの広告ウィンドウサイズを記録する
                if(hdr.ipv4.srcAddr == 0x0a000202){
                    ackNo_reg.write(1, (bit<32>)hdr.tcp.window);
                }else if(hdr.ipv4.srcAddr == 0x0a000505){
                    ackNo_reg.write(2, (bit<32>)hdr.tcp.window);
                }else if(hdr.ipv4.srcAddr == 0x0a000606){
                    ackNo_reg.write(3, (bit<32>)hdr.tcp.window);
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
        //ipv4のチェックサム再計算
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


        // TCPのチェックサム再計算
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
              //hdr.rheader.remaining_header,
              hdr.payload.deq_timedelta,
              hdr.payload.sep1,
              hdr.payload.enq_qdepth,
              hdr.payload.sep2,
              hdr.payload.deq_qdepth,
              hdr.payload.sep3,
              hdr.payload.qid,
              hdr.payload.sep4,
              hdr.payload.ackNo_reg,
              hdr.payload.sep5,
              hdr.payload.counter,
              hdr.payload.sep6,
              hdr.payload.data
            },         
            hdr.tcp.checksum,
            HashAlgorithm.csum16);     


        update_checksum_with_payload(    // ペイロードを含むチェックサム計算
            (hdr.tcp.isValid() && !hdr.payload.isValid()),           // TCPが有効な場合にのみ計算
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
              hdr.tcp.urgentPtr          // TCP: Urgent Pointer
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
        //packet.emit(hdr.rheader);
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
