# Static Analyzer Toolset

This directory contains a static analysis tool designed to detect buffer overflow vulnerabilities caused by unsafe usage of command-line arguments (`argv`).

## Key Scripts

### 1. `static_analyzer.py`
The main analysis engine that identifies paths from `argv` inputs to vulnerable sink functions.

**Key Features:**
- **Hybrid Analysis**: Combines Control Flow Graph (CFG) analysis using `angr` with lightweight disassembly parsing using `objdump`.
- **Vulnerability Detection**: Specifically targets buffer overflow sinks: `strcpy`, `strcat`, `gets`, `sprintf`, and `memcpy`.
- **Argv Tracking**: Attempts to track which specific command-line argument (`argv[1]`, `argv[2]`, etc.) flows into a vulnerable function.
- **Call Graph Construction**: Builds a call graph to trace execution paths from `main` to potential sinks.
- **AI Integration**: Can optionally leverage an AI analyzer to verify findings and reconstruct C code from assembly for better context.
- **Reporting**: Outputs a text-based report categorizing vulnerabilities by sink type and risk level.

**Implementation Details:**
The analyzer works in three steps:
1.  **Build Call Graph**: Uses `angr` (or `objdump` as fallback) to map function calls within the binary.
2.  **Find Argv Usage**: Analyzes the `main` function to detect how `argv` is accessed and passed to other functions. It looks for x86-64 patterns (e.g., access via `rsi` register).
3.  **Trace Paths**: Performs a Breadth-First Search (BFS) on the call graph to find paths from `argv` sources to known sink functions. It uses a hybrid approach, combining call graph reachability with parameter tracking to reduce false positives.

### 2. `ai_analyzer.py`
An AI-powered module that enhances the static analysis by providing semantic understanding of the binary code.

**Key Features:**
- **C Code Recovery**: Uses Large Language Models (LLMs) to reconstruct C code from the binary's assembly instructions.
- **Bulk Path Analysis**: Analyzes potential vulnerability paths identified by the static analyzer to determine if they are "True Positives" or "False Positives".
- **Multi-Provider Support**: Supports both Google Gemini and OpenAI models.

**Implementation Details:**
The module constructs prompts containing the assembly code or identified paths and sends them to the configured LLM provider. It parses the LLM's JSON response to provide a verdict and reasoning for each potential vulnerability, helping to filter out false alarms (e.g., cases where bounds checks exist but were missed by the static analysis).

## Usage

**Basic Static Analysis:**
```bash
python static_analyzer.py <path_to_binary>
```

**With AI Enhancement:**
Ensure you have the appropriate API key set in your environment (`GOOGLE_API_KEY` or `OPENAI_API_KEY`).
```bash
# The static analyzer likely has a flag to enable AI mode, e.g.:
# python static_analyzer.py <path_to_binary> --ai google
```
*(Note: Check `static_analyzer.py` arguments for exact AI enabling flags)*

