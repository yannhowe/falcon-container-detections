# Falcon Container Detections

Detection content repo for CrowdStrike Falcon — Docker image with attack simulation scripts, K8s manifests for workload-based tests, and a verification script to check results via Falcon API.

## Quick Start

### Docker (simplest)

```bash
make build
make run                              # Run all 19 scenarios
make run-single SCRIPT=01-container-escape.sh  # Single scenario
```

### Kubernetes

```bash
make deploy-k8s                       # Deploy CronJob + test workloads
make run-k8s                          # Trigger immediate run
make verify                           # Check scorecard
make clean                            # Tear down
```

## What It Tests

### Runtime Detections (16 proven + 3 best-effort)

| # | Script | Detection | Severity |
|---|--------|-----------|----------|
| 1 | container-escape | ContainerEscape (cgroup) | High |
| 2 | container-escape-chroot | ContainerEscape (chroot) | High |
| 3 | fileless-memfd | ElfExecutedFromMemory | High |
| 4 | reverse-shell-python | GenPersistenceLin + BashReverseShell | High |
| 5 | reverse-shell-perl | BashReverseShell | High |
| 6 | reverse-shell-ruby | BashReverseShell | High |
| 7 | webshell-cmd-injection | LinWebshell + WebshellLinSession | High |
| 8 | credential-dumping | CredentialTheftLin | High |
| 9 | rootkit-jynx | JynxRootkitInstall | Critical |
| 10 | suspicious-cli | GenExecutionLin | High |
| 11 | credential-collection | GenCollectionLin | High |
| 12 | dns-exfiltration | ExfilViaDNSRequest | High |
| 13 | ransomware-lockbit | LinProcRansomware | High |
| 14 | container-drift | ContainerDrift | Medium |
| 15 | reverse-shell-trojan | LapsangSensorDetect (ML) | High |
| 16 | eicar-malware | OnWrite-MLSensor | High |
| 17 | imds-exfil | *(best-effort)* | — |
| 18 | lateral-movement | *(best-effort)* | — |
| 19 | cryptominer | *(best-effort)* | — |

### Workload-Based Tests (K8s)

| Manifest | Tests |
|----------|-------|
| `detections-cronjob.yaml` | All detection scripts on schedule |
| `workloads-compliant.yaml` | Baseline telemetry (nginx, redis) |
| `workloads-misconfigured.yaml` | IOM: privileged, hostNetwork, root, no-limits |
| `workloads-vulnerable.yaml` | Image assessment: nginx:1.21, python:3.8, alpine:3.14 |
| `kac-block-test.yaml` | KAC admission rejection |
| `drift-test.yaml` | Container drift detection |

## Configuration

Copy `.env.example` to `.env` and fill in your Falcon API credentials:

```bash
cp .env.example .env
# Edit .env with your credentials
```

## Verification

```bash
python verify/check.py          # Default: last 4 hours
python verify/check.py --hours 8 --verbose
```

## Prerequisites

- **Docker host**: Falcon sensor installed, `--privileged` for container escape tests
- **EKS/GKE**: Falcon DaemonSet + KAC deployed
- **CSPM**: AWS/GCP account registered for IOM detection
- **Verify**: Python 3.9+, FalconPy (`pip install -r verify/requirements.txt`)
