# ICMP_Sonar Lab Replay

This is a Linux C replay framework for the paper "Rumors Stop with the Wise".
It reproduces the decision logic, scheduling flow, and deployment classification
using lab observations from CSV.

Current implementation focuses on a safe lab input path:
- IPv4 targets come from `--ipv4-cidr`
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
  --ipv4-cidr 192.168.10.0/29 \
  --ipv6-csv sample_ipv6_targets.csv \
  --ports 22,53,80,443 \
  --methods unreachable,fragmentation \
  --mtu 1300 \
  --cooldown 600 \
  --retry-missing 1
```

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
