# prom_exporter bird部分

先用python熟悉一下，看一下具体哪些bird的参数需要被探针记录  
主要要实现的是对bgp的监控，对babel的监控可以先放一边，ospf这些之后有空再弄

## bgp需要监控的参数

bird_output.txt里有ibgp 成功和失败的ebgp的参考输出  
主要以状态监控为主，先不protocols all，先protocols实现一下检测bgp up/down以及记录bgp在bird中的接口名用于之后对详细信息的获取  

```shell
ibgp_skus  BGP        ---        up     15:07:37.723  Established
as0298     BGP        ---        start  2026-07-17    Connect       BGP Error: Hold timer expired
```

这个是参考的输出，我需要获取并确认是bgp协议，然后记录协议名到列表/切片，然后获取最后的 Established/Connect/down，这个是具体的状态信息，时间对我来说不重要，第四个值和第六个值冗余了，所以跳过获取

```shell
ibgp_hham  BGP        ---        up     00:13:33.917  Established   
  BGP state:          Established
    Neighbor address: 172.20.192.101
    Neighbor AS:      4242420306
    Local AS:         4242420306
    Neighbor ID:      172.20.192.101
    Local capabilities
      Multiprotocol
        AF announced: ipv4 ipv6
      Route refresh
      Extended message
      Graceful restart
      4-octet AS numbers
      ADD-PATH
        RX: ipv4 ipv6
        TX: ipv4 ipv6
      Enhanced refresh
      Long-lived graceful restart
    Neighbor capabilities
      Multiprotocol
        AF announced: ipv4 ipv6
      Route refresh
      Extended message
      Graceful restart
      4-octet AS numbers
      ADD-PATH
        RX: ipv4 ipv6
        TX: ipv4 ipv6
      Enhanced refresh
      Long-lived graceful restart
    Session:          internal multihop AS4
    Source address:   172.20.192.98
    Hold timer:       198.810/240
    Keepalive timer:  26.241/80
    Send hold timer:  395.275/480
  Channel ipv4
    State:          UP
    Table:          master4
    Preference:     100
    Input filter:   ACCEPT
    Output filter:  ACCEPT
    Routes:         1091 imported, 14 exported, 3 preferred
    Route change stats:     received   rejected   filtered    ignored   accepted
      Import updates:           3055          0          0        315       2740
      Import withdraws:           63          0        ---          0         63
      Export updates:         280823     280377          0        ---        446
      Export withdraws:          172        ---        ---        ---          0
    BGP Next hop:   172.20.192.98
    IGP IPv4 table: master4
  Channel ipv6
    State:          UP
    Table:          master6
    Preference:     100
    Input filter:   ACCEPT
    Output filter:  ACCEPT
    Routes:         1122 imported, 2 exported, 7 preferred
    Route change stats:     received   rejected   filtered    ignored   accepted
      Import updates:           2988          0          0          0       2988
      Import withdraws:           60          0        ---          0         60
      Export updates:          35507      35505          0        ---          2
      Export withdraws:          279        ---        ---        ---          0
    BGP Next hop:   fd6e:a078:8f95::2
    IGP IPv6 table: master6
```

这个是bgp的输出，name在获取的时候其实就已经知道了，所以没必要获取，跳过前三行  
两侧的AS号需要获取，然后就是Channel里ipv4/ipv6得分开，然后获取里面的Routes,剩下的route change先不管，等以后有空再说

然后还有bgp会话数量也记录下，不过这个好像可以交给面板

## babel需要监控的参数

babel比较简单，记录邻居数，然后记录邻居的RTT就可以了
