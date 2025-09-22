# Sample Queries
## Sample Dashboard
### 1. トラフィックの可視化

- **許可/拒否リクエスト数の推移**  
時系列グラフで、許可と拒否のリクエスト数を比較。攻撃や誤設定を把握。
    ```
    'Log Source' = 'OCI Network Firewall Traffic Logs' | timestats count as logrecords by Action
    ```
    ![alt text](./images/sample-nfw-1_1.png)


- **接続元IPアドレスのトップランキング**  
バーチャートやテーブルで、最も多いアクセス元を可視化。特定の国やIPから集中していないか確認。
    ```
    'Log Source' = 'OCI Network Firewall Traffic Logs' | geostats count as logrecords | sort -logrecords
    ```
    ![alt text](./images/sample-nfw-1_2.png)

    ```
    'Log Source' = 'OCI Network Firewall Traffic Logs' | stats count as logrecords by 'Client Host Country' | sort -logrecords
    ```
    ![alt text](./images/sample-nfw-1_3.png)

- **通信プロトコル/ポート別のトラフィック量**  
Pieや棒グラフで、TCP/UDPや特定ポートごとの割合を把握。
    ```
    'Log Source' = 'OCI Network Firewall Traffic Logs' | stats count as logrecords by 'Protocol (Transport)', 'Destination Port' | sort -logrecords
    ```
    ![alt text](./images/sample-nfw-1_4.png)

### 2. セキュリティインシデント検知

- **拒否されたトラフィックの上位ルール**  
どのポリシーやルールで拒否されているかを可視化。

- **異常な通信パターン検知**  
通常と異なる時間帯や国からのアクセスをヒートマップで表示。

- **脅威インジケータとの突合結果**  
OCI Threat Intelligenceと連携して、既知の悪性IPからのアクセス数をグラフ化。

### 3. パフォーマンスと利用状況

- **ファイアウォールルールごとのヒット数**  
使用されていないルールや過剰にヒットしているルールを可視化 → チューニングの材料に。

- **処理したセッション数の推移**  
トラフィック負荷を時系列で確認し、スケーリングの検討材料に。

- **ログ生成量の傾向**  
ファイアウォールの稼働状況を俯瞰。

### 4. ユーザー/組織への報告用ダッシュボード

- **セキュリティインシデントサマリー（拒否数・検知数）**

- **地理的なアクセス分布マップ**

- **週次/月次の利用統計**


## SFD
### Top 10 Denied Destination Ports

```
'Log Source' in ('OCI Network Firewall Traffic Logs', 'OCI Network Firewall Threat Logs') and Action like 'drop%' or Action = 'reset-both' | link 'Destination Port', 'Source IP' | fields -'Start Time', -'End Time'
```

![alt text](./images/sfd-top10DeniedDestinationPorts.png)


### Top 10 Allowed Destination Ports
```
'Log Source' in ('OCI Network Firewall Traffic Logs', 'OCI Network Firewall Threat Logs') and Action in (allow, alert) | link 'Destination Port', 'Source IP' | fields -'Start Time', -'End Time'
```

![alt text](./images/sfd-top10AllowedDesticationPorts.png)


### Top 10 Denied Sources
```
'Log Source' in ('OCI Network Firewall Traffic Logs', 'OCI Network Firewall Threat Logs') and Action in (deny, drop, 'reset-both', 'drop-icmp') | stats count as 'Denied Connections' by 'Source IP' | top 'Denied Connections'
```

![alt text](./images/sfd-top10DeniedSources.png)


### Top 10 Source IPs
```
'Log Source' in ('OCI Network Firewall Traffic Logs') | stats count by 'Source IP' | top Count
```

![alt text](./images/sfd-top10SourceIps.png)


### Top 10 Destination IPs
```
'Log Source' in ('OCI Network Firewall Traffic Logs') | stats count by 'Destination IP' | top Count
```

![alt text](./images/sfd-top10DestinationIps.png)


### Policy hit count by name
```
'Log Source' in ('OCI Network Firewall Traffic Logs') | link Rule, Action, Entity | rename Entity as Firewall | stats avg('Packets In') as 'Packets In', latest(Time) as Latest_Hit
```
![alt text](./images/sfd-policyHitCountByName.png)


### Threat Logs By Threat Subtype Device
```
'Log Source' = 'OCI Network Firewall Threat Logs' | link Severity, Threat, 'Protocol (Transport)', Subtype | stats unique(Entity) as Firewall, unique('Threat Category') as 'Threat Category', unique(Action) as Action | eval score = if(Severity = critical, 10, Severity = high, 8, Severity = medium, 5, Severity = low, 2, Severity = informational, 1, 0) | sort -score, -Count | fields -'Start Time', -'End Time', -score | classify topcount = 300 correlate = -*, Action, 'Threat Category' Severity, Subtype, Threat as 'Threat Analysis'
```

![alt text](./images/sfd-threatLogsByThreatSubtypeDevice.png)

