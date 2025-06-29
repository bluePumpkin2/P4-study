import pyshark
import sys

###How To Use###
#「python [このファイル名] [pcapngファイル名] > [出力するCSVファイル名(.csv)]」で実行（[]は不要）
# 出力は「実行時間[s],RTT[ms]」となる
# このcsvファイルをExcelで開き、A列とB列を全選択して、挿入->散布図(平滑線とマーカー)でグラフ化

args = sys.argv
cap = pyshark.FileCapture(args[1])
ACKcheck = [None] * 1000000     #100万パケットを超える場合はこの「* 1000000」を「* 1500000」などとする
for i in range(len(ACKcheck)):
    ACKcheck[i] = [None] * 5

def analyze(capture):
    packet_loop = 0
    for packet in capture:
        if 'tcp' in packet:               
            used = False
            number = packet.number
            seqNo = packet.tcp.seq_raw
            ackNo = packet.tcp.ack_raw
            segLen = packet.tcp.len
            timestamp = packet.sniff_timestamp
            ACKcheck[packet_loop][0] = used
            ACKcheck[packet_loop][1] = number
            ACKcheck[packet_loop][2] = seqNo
            ACKcheck[packet_loop][3] = segLen
            ACKcheck[packet_loop][4] = timestamp
            
            '''
            #print(number, end="  ")
            if packet.ip.src == "10.0.1.1":
                print("DATA", end="  ")
                print("seq = " + seqNo, end="  ")
                print("ack = " + ackNo, end="  ")
                print("time = " + timestamp, end="  ")
            '''

            if packet.ip.src == "192.168.10.132":  #h2以外がreceiverの場合はここを適切なIPアドレスに書き換える
                '''
                print("ACK ", end="  ")
                print("seq = " + seqNo, end="  ")
                print("ack = " + ackNo, end="  ")
                print("time = " + timestamp, end="  ")
                '''
                
                for row in ACKcheck[packet_loop::-1]:
                    if row[2] == str(int(ackNo) - 1460):
                        print("{},{}".format(float(timestamp) - float(ACKcheck[0][4]), (float(timestamp) - float(row[4])) * 1000))
                        
                        '''
                        print("[", end="")
                        print(row[1], end=", ")
                        print(float(timestamp) - float(row[4]), end="")
                        print("]", end="  ")
                        '''
                        
                        break
                    
            packet_loop = packet_loop + 1

analyze(cap)
cap.close()