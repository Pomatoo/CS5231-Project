# Fuzzer Toolset

This directory contains tools for fuzzing binary applications using AFL (American Fuzzy Lop) with enhanced capabilities for argument fuzzing and crash analysis.

## Key Scripts

### 1. `afl_fuzzer.py`
A comprehensive Python wrapper for AFL that automates the fuzzing process and provides detailed crash analysis.

**Key Features:**
- **Automated Fuzzing**: Manages the AFL fuzzing session, handling input/output directories and timeouts.
- **Multiple Modes**:
    - `qemu`: Uses QEMU mode for binary-only fuzzing (no source code required).
    - `gcc`: Standard AFL mode for compiled binaries.
    - `dynamorio`: Uses DynamoRIO for instrumentation (requires `DYNAMORIO_HOME` environment variable).
- **Crash Analysis**:
    - **GDB Integration**: Automatically analyzes crashes using GDB to extract signal information, fault addresses, backtraces, and register states.
    - **Exploitability Assessment**: Heuristically scores crashes based on indicators like control over the instruction pointer (RIP), execution of illegal instructions, or crashes in known vulnerable functions.
    - **Input Dependency Check**: Determines if a crash is reliably triggered by the input and if the input directly influences the crash state (e.g., overwriting registers).
- **Reporting**: Generates a detailed JSON report (`crash_report.json`) and prints a summary of findings.

**Implementation Details:**
The script uses `subprocess` to launch AFL and monitor its progress. Upon completion or timeout, it scans the output directory for crashes. For each crash, it runs GDB in batch mode with a custom script to gather runtime state. It also performs a "direct test" by running the binary with the crashing input to verify reproducibility.

### 2. `create_wrappers.py`
A utility to generate C wrapper programs that allow AFL to fuzz command-line arguments of a target binary.

**Key Features:**
- **Argument Fuzzing**: AFL typically fuzzes standard input or file input. This script creates a wrapper that reads AFL's input from a file and passes it as a specific command-line argument to the target binary.
- **Automated Generation**: Generates C source code for the wrapper, handling memory allocation and argument construction.
- **Compilation**: Automatically compiles the generated wrapper using `gcc`.
- **Run Scripts**: Creates helper shell scripts (`run_<wrapper_name>.sh`) to easily start the fuzzing process for a specific argument.

**Implementation Details:**
The script takes the target binary path, total number of arguments, and indices of arguments to fuzz as input. It generates a C file that:
1. Reads the input file provided by AFL.
2. Constructs an argument list (`argv`) where the target index is replaced by the file content, and other arguments are set to static defaults.
3. Uses `execv` to replace the wrapper process with the target binary, preserving the fuzzed arguments.

## Usage

1.  **Generate Wrappers**:
    ```bash
    python create_wrappers.py <path_to_vuln_binary> <total_args> <fuzz_indices>
    # Example: python create_wrappers.py ./vuln 3 1,2
    ```

2.  **Run Fuzzing**:
    Execute the generated shell script or run `afl_fuzzer.py` directly:
    ```bash
    ./run_vuln_wrapper_arg1.sh
    # OR
    python afl_fuzzer.py -b ./vuln_wrapper_arg1 -i seeds -o findings
    ```
