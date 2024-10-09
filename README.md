工学院大学での学部と修士のP4研究の成果物です。実験環境はP4チュートリアルを利用させていただいております。https://github.com/p4lang/tutorials/tree/master

### CountPacket.p4
- P4チュートリアルの全ての演習を完了した後、自力でP4プログラムを書けるようになるために作成した簡単なパケットカウントプログラム。
- P4プログラム内でカウンタを読み取りたいのでレジスタを使った。
- pingとiperf3を実行するため、ICMPとTCPパケットに対応。
- 実際にカウントしていることを確かめるために、pingでは10回以降でパケットドロップし、iperf3では10000パケット以降、1000パケットに一回パケットドロップしている。

### TCPheader_rewrite.p4
- scapyでは送信速度が20~30pps程度で今後の研究に向かないと考えたので、iperf3を使う。
- レジスタの値やstandard_metadataの値を読み取る方法はScapyで読み取るかパケットに直接書き込むかしかなさそうなので、TCPヘッダに書き込む方法を取った。
- TCPチェックサムの再計算を実装し、ヘッダの一部を書き換えてもiperf3が通るようにした。

### PartialPayload_rewrite.p4
- TCPヘッダだけでは書き込める箇所が少なく、19bitのstandard_metadata.qdepthなどを書き込めないのでペイロードに書き込めるようにした。
- まずは固定長のペイロードに書き込めるようにした。
- TCPヘッダのurgentPtr以降もTCPヘッダが続くが、パケットによって違いがあった。1024byte以上のパケットは全て同じだったのでその通りに定義した。
- ペイロードも含めたTCPチェックサム再計算も実装した。

### AllPayload_capture&rewrite.p4
- urgentPtr以降のTCPヘッダもvarbitで定義することで、全てのパケットに対して全てのペイロードをパースし、書き換えることができるようになった。
