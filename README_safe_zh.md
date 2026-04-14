# ISAV 审计工具（安全受限版）

本实现基于论文《Rumors Stop with the Wise》的测量流程思想（目标筛选 + 结果归类），但不包含伪造源地址 ICMP 报文与互联网全网扫描能力。

原因：伪造源地址 + 全网扫描属于高风险网络攻击能力。

## 功能
- IPv4：扫描你指定的 RFC1918 私网 CIDR（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 子集）。
- IPv6：从 CSV 读取地址（每行一个地址，或第一列是地址）。
- 对每个目标探测 TCP 端口：22/53/80/443。
- 输出 CSV：`ip_version,target,open_port_count,open_ports`。

## 编译
```bash
gcc -O2 -Wall -Wextra -o isav_audit_safe isav_audit_safe.c
```

## 运行
仅 IPv4：
```bash
./isav_audit_safe --ipv4-cidr 192.168.1.0/24 --out result_v4.csv
```

仅 IPv6：
```bash
./isav_audit_safe --ipv6-csv ipv6_targets.csv --out result_v6.csv
```

双栈：
```bash
./isav_audit_safe --ipv4-cidr 10.10.0.0/24 --ipv6-csv ipv6_targets.csv --out result_all.csv
```

可选参数：
- `--timeout 800`：TCP 连接超时毫秒数（100~10000）。

## IPv6 CSV 示例
```csv
2001:db8::1
240e:xxxx:xxxx::2
```

## 论文方法要点（简述）
- ICMP Unreachable 方法：比较发送 ICMP 不可达前后的 TCP 重传差异（论文阈值：`n1 - n2 >= 2`）。
- ICMP Fragmentation 方法：通过 ICMP fragmentation needed 影响 PMTU，再检测回包是否分片。
- 论文中 IPv4 可全网扫描；IPv6 使用 hitlist。文中常用 MTU 字段为 1300，步进间隔建议 >=10 分钟以避免相互干扰。

如果你有已授权的实验网络，我可以继续给你补一版“实验室复现脚手架”（离线/仿真输入），用于复现论文判定逻辑与统计结果，不涉及伪造报文外发。
## 结果分类工具

新增文件：`isav_result_classifier.c`

用途：将你在授权实验环境里拿到的主机观测结果，按论文口径写成部署分类 CSV。

输入 CSV 必须包含列：
`ip_version,target,method,result`

- `ip_version`: `4` 或 `6`
- `target`: IP 地址
- `method`: `unreachable` 或 `fragmentation`（当前仅记录，不影响判定）
- `result`: `intercepted` 或 `not_intercepted`

判定规则：
- 全部 `intercepted` -> `Deployed ISAV`
- 全部 `not_intercepted` -> `No ISAV`
- 两者都出现 -> `Partial ISAV`

### 编译
```bash
gcc -O2 -Wall -Wextra -o isav_result_classifier isav_result_classifier.c
```

### 运行
主机粒度：
```bash
./isav_result_classifier host_observations.csv host deployment_host.csv
```

子网粒度（IPv4按/24，IPv6按/40）：
```bash
./isav_result_classifier host_observations.csv subnet deployment_subnet.csv
```
