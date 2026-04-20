# ICMP_Sonar Lab Replay

This is a Linux C replay framework for the paper "Rumors Stop with the Wise".
It reproduces the decision logic, scheduling flow, and deployment classification
using lab observations from CSV.

Current implementation focuses on a safe lab input path:
- IPv4 targets come from `--ipv4-cidr`
- or use `--ipv4-global` to sample from global IPv4 space
- or use `--ipv4-global-progressive` to probe global IPv4 sequentially across runs
- IPv6 targets come from `--ipv6-csv`
- observations come from `--capture-observations`
- outputs are host-level and deployment-level CSV files

## Build

```bash
make
```

## Run

```bash
./icmp_sonar_lab \
  --iface lab0 \
  --capture-observations sample_lab_observations.csv \
  --out-prefix output/run1 \
  --ipv4-global \
  --ipv4-global-limit 4096 \
  --ipv6-csv sample_ipv6_targets.csv \
  --ports 22,53,80,443 \
  --methods unreachable,fragmentation \
  --mtu 1300 \
  --cooldown 600 \
  --retry-missing 1
```

`--ipv4-global` 会在 `0.0.0.0/0` 空间均匀采样地址，数量由 `--ipv4-global-limit` 控制（默认 `4096`，最大 `65536`）。

`--ipv4-global-progressive` 会按顺序批量探测全网 IPv4：  
- 每次运行探测一批，批大小由 `--ipv4-global-batch-size` 控制（默认 `4096`，最大 `65536`）  
- 进度写入 `--ipv4-global-cursor-file`（默认 `.ipv4_global_cursor`）  
- 多次重复运行会逐步覆盖整个 IPv4 空间（循环跳过 `0.0.0.0` 与 `255.255.255.255`）

### Prefix-AS 批量检测模式（按 AS 早停）

输入 txt 格式（制表符分隔）：`<prefix>\t<asn>`，例如：

```txt
1.0.0.0/24	13335
1.0.4.0/24	38803
2001:db8::/120	64500
```

执行命令：

```bash
./icmp_sonar_lab \
  --iface lab0 \
  --capture-observations sample_lab_observations.csv \
  --prefix-as-v4-txt v4_prefix_as.txt \
  --prefix-as-v6-txt v6_prefix_as.txt \
  --no-isav-addr-csv no_isav_address.csv \
  --no-isav-as-csv no_isav_as.csv \
  --ports 22,53,80,443 \
  --methods unreachable,fragmentation
```

逻辑说明：
- 程序会遍历每个前缀下的地址并判断是否 `not_intercepted`（视为该地址未部署 ISAV）。
- 一旦某个 AS 找到一个未部署 ISAV 的地址，则该 AS 后续前缀全部跳过。
- 最终输出两个 CSV：
  - `no_isav_address.csv`：未部署 ISAV 的地址明细（含 ASN、prefix、target）
  - `no_isav_as.csv`：未部署 ISAV 的 ASN 列表（首次命中的 prefix 与 target）

## Capture CSV

Header:

```csv
ip_version,target,method,port,attempt,meas_n1,meas_n2,meas_baseline_fragmented,meas_post_fragmented,detect_n1,detect_n2,detect_baseline_fragmented,detect_post_fragmented,missing,note
```

Fields:
- `ip_version`: `4` or `6`
- `target`: target address
- `method`: `unreachable` or `fragmentation`
- `port`: real port for `unreachable`, `0` for `fragmentation`
- `attempt`: starts at `0` and works with `--retry-missing`
- `meas_*`: measurable-target stage observations
- `detect_*`: spoofed-probing decision stage observations
- `missing`: `1` means the attempt is missing and should be retried
- `note`: lab note for the record

Decision rules:
- `unreachable`
  - measurable if `meas_n1 - meas_n2 >= 2`
  - `detect_n1 - detect_n2 >= 2` means `not_intercepted`
  - otherwise `intercepted`
- `fragmentation`
  - measurable if `meas_baseline_fragmented == 0 && meas_post_fragmented == 1`
  - `detect_post_fragmented == 1` means `not_intercepted`
  - otherwise `intercepted`

## Outputs

Host-level CSV:

```csv
timestamp,ip_version,target,method,port,measurable,result,n1,n2,baseline_fragmented,post_fragmented,retry_count,note
```

Deployment CSV:

```csv
ip_version,scope,classification,method_coverage,observation_count
```

Aggregation rules:
- IPv4 is grouped by `/24`
- IPv6 is grouped by `/40`
- if one target shows both `intercepted` and `not_intercepted` across methods,
  the target and its scope are written as `Unmeasurable`
