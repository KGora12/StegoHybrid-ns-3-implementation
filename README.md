# StegoHybrid

This repository contains the code for StegoHybrid. It provides everything needed to run and evaluate a fully hybrid steganographic channel that combines the PHY and MAC layers of IEEE 802.11ax, implemented in ns-3 (version 3.44).

The hybrid channel consists of two main covert sub-channels:

- **PHY sub-channel (Next-generation dirty constellation).** Secret bits are embedded by displacing selected QAM-16 symbols into an elliptical ring around their nominal constellation points. The receiver recovers them from symbols that fall outside an inner decision ellipse.
- **MAC sub-channel (TXOP Duration utilization).** Secret bits are encoded in the TXOP duration utilization by building frames of specific lengths, alternating between the AC_VO and AC_VI access categories.

A controller decides in each step whether only the PHY sub-channel is used or whether a TXOP symbol is sent as well.

## Repository structure


.
├── ns3/
│   ├── scratch/
│   │   ├── channel_s1.cc             # Scenario 1: PHY covert channel (16-QAM steganography, SNR sweep)
│   │   ├── channel_s2_4.cc           # Scenarios 2–4: Hybrid PHY/MAC covert channel
│   │   ├── channel_PHY_sec.cc        # Detectability analysis: PHY covert channel
│   │   ├── channel_MAC_sec.cc        # Detectability analysis: MAC covert channel
│   │   └── channel_legacy_sec.cc     # Detectability analysis: Legacy covert channel
│   └── src/wifi/model/               # Reference copies of the required ns-3.44 Wi-Fi model files
├── data/
│   ├── scenario1/
│   │   ├── SNR/data_s1.csv                      # PER, BER, and covert BER as functions of SNR
│   │   └── constellation/all_constellation/...  # Transmitted and received constellation points for each SNR
│   ├── scenario2/data_s2/                       # Scenario 2 simulation results
│   ├── scenario3/data_s3/                       # Scenario 3 simulation results
│   └── scenario4/data_s4/                       # Scenario 4 simulation results
├── LICENSE
└── README.md

## Usage

### Scenario 1: PHY sub-channel

Simulates QAM-16 steganography over 802.11ax (HE-MCS3, 20 MHz) for a given SNR and set of ellipse thresholds.


Example usage:
```bash
./ns3 run "channel_s1 --snrDb=24"
```

Main parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--snrDb` | SNR in dB used to generate EVM-based noise | 24 |
| `--e1` | Inner ellipse threshold (decoder) | 1/300 |
| `--e2` | Lower bound of the embedding ring | 1/70 |
| `--e3` | Upper bound of the embedding ring | 1/40 |
| `--sim` | Simulation time in seconds | 300 |
| `--data` | UDP payload size in bytes | 2000 |

Each run appends one row (`snr_db, qam_per, qam_ber, hidden_ber, e1, e2, e3`) to `data_s1.csv` and writes the constellation of the first packet to `all_constellation/<e1>_<e2>_<e3>/all_constellation_<snr>.csv`.


### Scenarios 2–4: hybrid channel

Simulates the hybrid PHY + MAC channel with optional background stations.

```bash
# Adaptive TXOP Mode: --pOne controls how often the TXOP sub-channel is used
# (higher values = more frequent use, lower values = less frequent use)
./ns3 run "channel_s2_4 --pOne=0.2"

# Only Physical Layer Mode: QAM steganography only
./ns3 run "channel_s2_4 --random=0 --combo=0"

# TXOP Full-Usage Mode: a TXOP symbol is sent in every step
./ns3 run "channel_s2_4 --random=0 --combo=1"
```

Main parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--random` | Random hybrid mode (1) or fixed cyclic pattern (0) | 1 |
| `--pOne` | Random mode: probability of a QAM + TXOP step | 0.2 |
| `--combo` | Cyclic pattern used when `random=0` (`0` = QAM, `1` = QAM + TXOP) | `0` |
| `--snrDb` | QAM Es/N0 in dB | 26 |
| `--stations` | Number of background stations | 0 |
| `--bgRate` | Traffic rate per background station | 25Mbps |
| `--legBgRate` | Target QAM rate (`0Mbps` disables QAM) | 5Mbps |
| `--sim` | Simulation time in seconds | 300 |
| `--csv` | Output CSV file | `hybrid_cc_results.csv` |

Run `./ns3 run "channel_s2_4 --help"` for the full list of parameters.

Each run prints a report and appends one row to the CSV file with TXOP goodput, delay and jitter, QAM PER/BER and goodput, hidden BER and goodput, and IP-level metrics from FlowMonitor.


### Detectability analysis

The detectability analysis evaluates whether covert transmissions can be distinguished from regular IEEE 802.11ax traffic.

Three simulation programs are provided:

- **`channel_PHY_sec.cc`** – Evaluates PHY sub-channel detectability by collecting received 16-QAM constellation points with and without steganographic modifications.
- **`channel_MAC_sec.cc`** – Evaluates MAC sub-channel detectability by recording TXOP duration utilization for different transmission modes.
- **`channel_legacy_sec.cc`** – Generates reference TXOP measurements from regular IEEE 802.11ax traffic for comparison.

Example usage:

```bash
# PHY detectability
./ns3 run "channel_PHY_sec --enableCovert=1 --dumpAll=1 --dumpPath=phy_covert.csv"
./ns3 run "channel_PHY_sec --enableCovert=0 --dumpAll=1 --dumpPath=phy_baseline.csv"

# MAC detectability
./ns3 run "channel_MAC_sec --mode=1"

# Legacy reference traffic
./ns3 run "channel_legacy_sec --ac=BOTH --csv=legacy_txop.csv"
```

The generated CSV files can be used for statistical comparison of constellation distributions (PHY) and TXOP utilization patterns (MAC) against regular traffic.

## Results

The `data/` directory contains the results used in the paper:

- `scenario1/` contains the PHY sub-channel results: error rates as a function of SNR and the sent/received constellation points.
- `scenario2/` – `scenario4/` contain the hybrid channel results for the three operating modes: *Only Physical Layer Mode*, *Adaptive TXOP Mode* and *TXOP Full-Usage Mode*.
- The datasets generated during the detectability analysis are not included in this repository due to their large size. These datasets can be reproduced using the provided simulation programs (`channel_PHY_sec.cc`, `channel_MAC_sec.cc`, and `channel_legacy_sec.cc`).
