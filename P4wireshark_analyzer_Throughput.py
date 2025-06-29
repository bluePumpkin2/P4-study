import sys
import pyshark

###How To Use###
#「python [このファイル名] [pcapngファイル名] > [出力するCSVファイル名(.csv)]」で実行（[]は不要）
# 出力は「ポート番号,実行時間[s],スループット[Mbit/s],1ちょいの値[s]」となる。1ちょいの値が1より無視できないほど大きいと何らかの不具合が発生している可能性がある
# このcsvファイルをExcelで開き、C列を全選択して、挿入->散布図(平滑線とマーカー)でグラフ化

args = sys.argv
cap = pyshark.FileCapture(args[1])

def analyze(capture):
    previous_timestamp = 0.0
    base_time = 0.0
    sum_len = 0
    sum_time = 0.0
    for packet in capture:
        if 'tcp' in packet and packet.ip.dst == '192.168.10.132': ##h2以外がreceiverの場合はここを適切なIPアドレスに書き換える
            IPlen = int(packet.ip.len)
            timestamp = float(packet.sniff_timestamp)
            
            sum_len = sum_len + IPlen + 14
            
            if previous_timestamp != 0.0:
                sum_time = sum_time + timestamp - previous_timestamp
            else:
                base_time = timestamp
                
            previous_timestamp = float(timestamp)
            
            if sum_time > 1:
                print("{},{:.20f},{},{:.20f}".format(packet.tcp.dstport, timestamp - base_time, sum_len * 8 / 1000000, sum_time))
                sum_len = 0
                sum_time = 0.0
                    
analyze(cap)
cap.close()