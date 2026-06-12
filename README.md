# Deanonymization Project README

This project is located in the `deanonymization` directory. It is designed for experiments on Monero's P2P network, including transaction propagation, graylist filling, whitelist filling, and connection reset attacks. The project contains four core subdirectories:

| Directory | Description |
| --- | --- |
| `Attack` | Sends stem-phase transactions to target nodes and performs graylist attacks. |
| `controller` | Performs whitelist attacks and connection reset attacks. |
| `levin_async` | Provides an asynchronous implementation of the Levin protocol used by `controller`. |
| `levin_sync` | Provides a synchronous implementation of the Levin protocol used by `controller`. |

> This README assumes that all required dependencies have already been installed and configured correctly.

## Directory Structure and File Descriptions

### 1. `Attack` Directory

| File / Directory | Description |
| --- | --- |
| `GraylistAttack.py` | Main program for graylist filling. |
| `node.py` | Simulates malicious node behavior, establishes connections with target nodes, and processes messages. |
| `send_stem_tx.py` | Sends stem-phase transactions to target nodes to determine their status. |
| `tools.py` | Common utility functions, such as timestamp generation and random IP generation. |
| `constants.py` / `async_constants.py` / `config` | Configuration files for local IP addresses, target node lists, `peer_id` mappings, and related settings. |
| `rpc` | Wallet-related implementation. |

### 2. `controller` Directory

| File | Description |
| --- | --- |
| `whitelist_fill.py` | Main program for whitelist filling and connection reset attacks. |
| `whitelist_fill_node_listener.py` | Listener used during whitelist filling. For each target node, a process and listening port are started to listen for Ping responses. After whitelist filling is complete, this program also listens for and replies to `handshake` and `timed_sync` messages to maintain the target node's outgoing connections. |
| `addr_peerid_map.json` | Manages the `peer_id` values for 1,000 whitelist attack nodes. In Monero, the `peer_id` declared in the handshake request must match the `peer_id` declared in the Ping response; otherwise, the Ping response is invalid. |
| `get_peerlist.py` | Retrieves the whitelist of a target node. |
| `generate_peer_id.py` | Utility script for generating `addr_peerid_map.json`. |
| `config.py` | Configuration file containing Monero network mode settings, database settings, server binding IP addresses, target node addresses, and the starting listening port. |

## FLUX Experiment Workflow

### Step 1: Start the Whitelist Filling Listener

This program generates `node_listener_{p2p_listening_port}.log` files under the `./log` directory. The number of log files corresponds to the number of target nodes in `target_node_list`.

```bash
screen -S whitelist_fill_node_listener
cd flux
python3 -m controller.whitelist_fill_node_listener
```

### Step 2: Start the Whitelist Filling Handshake Program

This program receives requests from the controller machine and performs whitelist filling on the specified target nodes.

```bash
screen -S whitelist_fill
cd flux
python3 -m controller.whitelist_fill
```

### Step 3: Start the Graylist Filling Program

```bash
screen -S GraylistAttack
cd flux/Attack
python3 GraylistAttack.py
```

## Data Analysis Workflow

### 1. Collect Log Files

Log in to the target node machine and obtain the generated `connections.log` file. Then download the following logs to the attacker's machine:

- `connections.log`
- `graylist.log`
- `whitelist.log`

### 2. Analyze Whitelist and Graylist Filling Results

Use the following scripts for experiment analysis:

| Script | Purpose |
| --- | --- |
| `analysis/analyze_whitelist.py` | Analyzes whitelist filling results. |
| `analysis/analyze_graylist.py` | Analyzes graylist filling results. |
| `analysis/analyze_graylist_connection_selection.py` | Analyzes graylist connection selection behavior. |

### 3. Analyze the 20-Round Connection Reset Experiment

Run:

```bash
python3 analyze_connections_20rounds.py
```

The script calculates two metrics according to the start and end time of each experiment round:

- The time from the start of the experiment until benign OUT connections drop to 0.
- The time from the end of the experiment until benign OUT connections recover to at least 2.

The results are saved as:

```text
20_rounds_time_cost_stats.csv
```

### 4. Plot the 20-Round Connection Reset Results

Run:

```bash
python3 20rounds_time_cost_bars.py
```

This script reads `20_rounds_time_cost_stats.csv` and generates two bar charts.

### 5. Analyze the Height Eligibility Experiment

Run:

```bash
python3 analyze_connection_counts.py
```

The script reads:

```text
2026-05-25_connections.log
```

### 6. Plot the Height Eligibility Results

Run:

```bash
python3 height_gte_self_plot.py
```

This script reads `malicious_height_gte_self_snapshots.csv` and generates the experiment figures.

## Recommended Execution Order

```text
1. Start whitelist_fill_node_listener
2. Start whitelist_fill
3. Start GraylistAttack
4. Collect connections.log / graylist.log / whitelist.log
5. Run the whitelist and graylist analysis scripts
6. Run the connection reset experiment analysis script
7. Run the plotting scripts to generate experiment figures
```

