# CS5231-Project
## Sink-to-source Vulnerability Discovery System (SVDS)

## Overview

The **Sink-to-source Vulnerability Discovery System (SVDS)** addresses the challenge of efficient vulnerability discovery by enabling targeted, sink-centric analysis. Given an input binary, SVDS identifies and traces all reachable function call paths, detects suspicious or insecure function usages, and reconstructs the path taken by attacker-controlled input to reach those vulnerable sinks.

Leveraging tools such as **angr** for static analysis and symbolic execution, **DynamoRIO** for dynamic binary instrumentation, and **Python** for orchestration, SVDS disassembles high-risk functions, reconstructs code structures, and determines whether filtering, bounds checking, or other mitigations are present. By highlighting the most likely vulnerable routes, SVDS enables targeted fuzzing and drastically improves research efficiency by narrowing the search space to execution paths with the highest likelihood of containing exploitable memory corruption vulnerabilities.

## Project Modules

This project consists of two main components:

### 1. [Static Analyzer](./Static%20Analyzer/README.md)
A hybrid analysis tool that combines Control Flow Graph (CFG) analysis with symbolic execution to identify paths from command-line arguments (`argv`) to vulnerable sink functions (e.g., `strcpy`, `gets`). It features:
- **Hybrid Analysis**: Uses `angr` and `objdump` to map execution paths.
- **AI Integration**: Optionally uses LLMs (Google Gemini/OpenAI) to reconstruct C code from assembly and verify false positives.
- **Vulnerability Reporting**: Categorizes findings by sink type and risk level.

### 2. [Fuzzer](./Fuzzer/README.md)
A comprehensive fuzzing suite built on top of AFL (American Fuzzy Lop) to validate findings and discover crashes. It features:
- **Argument Fuzzing**: Custom wrapper generation (`create_wrappers.py`) to fuzz command-line arguments.
- **Automated Crash Analysis**: Integrated GDB analysis to extract signals, backtraces, and register states from crashes.
- **Exploitability Scoring**: Heuristic assessment of crash exploitability and input dependency.
