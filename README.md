# Loki-IDS
Details Coming soon..

## Structure
```bash
loki-ids/
├─ README.md
├─ LICENSE
├─ .gitignore

├─ configs/
│  ├─ config.yaml
│  └─ policy.yaml

├─ ids/
│  ├─ loki/
│  │  ├─ nfqueue_app.py
│  │  ├─ packet_parser.py
│  │  ├─ detectors.py
│  │  ├─ state.py
│  │  ├─ logger.py
│  │  ├─ api.py
│  │  └─ utils.py
│  └─ requirements.txt

├─ kernel/
│  ├─ xdp_filter.c
│  ├─ loki_xdp_manager.py
│  └─ build_xdp.sh

├─ scripts/
│  ├─ install_deps.sh
│  ├─ iptables_up.sh
│  ├─ iptables_down.sh
│  ├─ run_loki_nfq.sh
│  ├─ gen_test_traffic.sh
│  └─ check_env.sh

├─ systemd/
│  └─ loki.service

├─ docs/
│  ├─ 02_setup_pi.md
│  ├─ 03_ids_nfqueue.md
│  ├─ 04_testing.md
│  └─ 05_xdp_future.md

├─ tests/
│  ├─ unit/
│  ├─ pcaps/
│  └─ replay_notes.md

├─ attack-scripts/
│  ├─ portscan.sh
│  ├─ flood_syn.sh
│  └─ README.md

├─ logs/
│  └─ .gitkeep

└─ .github/
   └─ workflows/
      └─ ci.yml
```

## 🗒️ Task Board (Development Tickets)

Below is the official task board for the Loki IDS project.  
Each task can be taken by any contributor.  
Reference the **Task ID** in your pull request branch names (e.g., `feature/T3-nfqueue-core`).

| ID | Category        | Task Description                                           | Status |
|----|-----------------|-------------------------------------------------------------|--------|
| **T1** | Setup          | Create and test `install_deps.sh` (apt + pip packages)       | 🟢 Done / Verify |
| **T2** | Setup          | Write `iptables_up.sh` and `iptables_down.sh`                | 🟡 In Progress |
| **T3** | Core IDS       | Implement NFQUEUE consumer loop (`nfqueue_app.py`)           | 🟡 In Progress |
| **T4** | Core IDS       | Implement packet parsing layer (`packet_parser.py` / Scapy)  | ⚪ Todo |
| **T5** | Detection      | Implement signature-based detection (blacklist lookup)       | ⚪ Todo |
| **T6** | Detection      | Implement port-scan detector (sliding window per-IP)         | ⚪ Todo |
| **T7** | Detection      | Implement rate-limit / DoS detection                          | ⚪ Todo |
| **T8** | Logging        | Implement JSONL logging system (`logger.py`)                 | ⚪ Todo |
| **T9** | API            | Build REST API for blacklist management & stats (Flask)      | ⚪ Todo |
| **T10** | Documentation | Write NFQUEUE design doc (`docs/03_ids_nfqueue.md`)          | ⚪ Todo |
| **T11** | Testing       | Build test suite with `nmap` / `hping3` scripted attacks     | ⚪ Todo |
| **T12** | Packaging     | Add `systemd` service (`loki.service`) for Pi autostart      | ⚪ Todo |
| **T13** | Kernel (Next) | Prototype XDP/eBPF fast-path (`kernel/xdp_filter.c`)         | 🔵 Planned |
| **T14** | CI/CD         | Add GitHub Actions: linting, unit tests                      | 🔵 Planned |

---

### 🧭 Task Status Legend
- 🟢 **Done**
- 🟡 **In Progress**
- ⚪ **Todo**
- 🔵 **Planned / Future Phase**

---

### 🛠️ How to Contribute
1. Pick any open task (⚪ Todo or 🔵 Planned).  
2. Create a branch:

```bash
git checkout -b feature/T<ID>-short-description
```
Example:
```bash
git checkout -b feature/T6-portscan-detector
```
3. Commit your work and open a Pull Request referencing the task ID.
