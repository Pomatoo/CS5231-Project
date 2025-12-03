#!/usr/bin/env python3
"""
DynamoRIO Trace Generator for AFL Crash Reports
Parses crash report JSON and generates traces with proper argument placement
"""

import subprocess
import os
import sys
import json
import random
import string
import shlex
import datetime

def parse_crash_report(json_path):
    """Parse AFL crash report JSON"""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    if not data.get('crashes'):
        print("[!] No crashes found in JSON")
        return None
    
    # Get first crash (or iterate through all)
    crash = data['crashes'][0]
    
    return {
        'binary': data['metadata']['binary'],
        'input_hex': crash['input']['hex'],
        'input_printable': crash['input']['printable'],
        'input_bytes': bytes(crash['input']['raw_bytes']),
        'crash_signal': crash.get('gdb_analysis', {}).get('exit_signal', 'Unknown'),
        'input_size': crash['input']['size']
    }


def generate_random_arg(length=10):
    """Generate random ASCII argument"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def extract_arg_position(binary_path):
    """Extract argument position from binary name
    
    Examples:
        five_args_vuln_wrapper_arg2 → position 2
        test_wrapper_arg4 → position 4
    """
    basename = os.path.basename(binary_path)
    
    # Look for _argN pattern
    import re
    match = re.search(r'_arg(\d+)', basename)
    if match:
        return int(match.group(1))
    
    return None


def build_argument_list(crash_input, arg_position, total_args, use_hex=False):
    """Build complete argument list with crash input at specific position
    
    Args:
        crash_input: The input that caused crash (bytes or str)
        arg_position: Which argument position to use (1-indexed)
        total_args: Total number of arguments the binary expects
        use_hex: If True, use hex representation; else use printable
    
    Returns:
        List of arguments for the binary
    """
    args = []
    
    # Convert crash input to string
    if use_hex:
        # Use hex representation
        if isinstance(crash_input, bytes):
            crash_str = crash_input.hex()
        else:
            crash_str = crash_input
    else:
        # Use printable representation
        if isinstance(crash_input, bytes):
            crash_str = crash_input.decode('latin-1', errors='ignore')
        else:
            crash_str = crash_input
    
    for i in range(1, total_args + 1):
        if i == arg_position:
            # Place crash input at this position
            args.append(crash_str)
            print(f"[*] Argument {i}: CRASH INPUT ({len(crash_str)} chars)")
        else:
            # Generate random filler
            filler = generate_random_arg(10)
            args.append(filler)
            print(f"[*] Argument {i}: {filler} (random filler)")
    
    return args


def run_with_dynamorio(binary, args_list):
    """Run binary under DynamoRIO with Peekaboo"""
    
    # Ensure output directory exists
    #os.makedirs(output_dir, exist_ok=True)
    
    # Build command
    cmd = [
        os.path.expanduser('~/project/DynamoRIO-Linux-11.3.0-1/bin64/drrun'),
        '-c', os.path.expanduser('~/project-dependencies/peekaboo/peekaboo_dr/build/libpeekaboo_dr.so'),
        '--',
        binary
    ] + args_list
    
    print(f"\n[*] Running command:")
    print(f"    {' '.join(cmd[:6])}  # DynamoRIO setup")
    print(f"    {' '.join(cmd[6:])}  # Binary + args")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = process.communicate(timeout=60)
        
        return {
            'return_code': process.returncode,
            'stdout': stdout.decode('utf-8', errors='ignore'),
            'stderr': stderr.decode('utf-8', errors='ignore'),
            'crashed': process.returncode != 0
        }
    
    except subprocess.TimeoutExpired:
        process.kill()
        return {
            'return_code': -1,
            'stdout': '',
            'stderr': 'Timeout',
            'crashed': True
        }


def find_latest_trace_dir():
    """Find the most recently created trace directory"""
    trace_dirs = []
    
    for item in os.listdir('.'):
        if os.path.isdir(item) and (item.startswith('vuln-') or 
                                     item.startswith('five_args-') or
                                     item.startswith('test-')):
            trace_dirs.append(item)
    
    if not trace_dirs:
        return None
    
    # Sort by creation time
    trace_dirs.sort(key=lambda x: os.path.getctime(x), reverse=True)
    return trace_dirs[0]


def generate_read_trace_commands(trace_dir):
    """Generate commands for read_trace"""
    # Find the inner directory (contains actual traces)
    subdirs = [d for d in os.listdir(trace_dir) if os.path.isdir(os.path.join(trace_dir, d))]
    if subdirs:
        inner_dir = os.path.join(trace_dir, subdirs[0])
    else:
        inner_dir = trace_dir
    
    commands = [
        f"read_trace -m {inner_dir} > memory.txt",
        f"read_trace -r {inner_dir} > register.txt",
        f"read_trace -y {inner_dir} > syscall.txt",
        f"python3 taint_analyzer.py {inner_dir} memory.txt register.txt syscall.txt"
    ]
    
    return inner_dir, commands


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_trace_from_json.py <crash_report.json> [options]")
        print()
        print("Required:")
        print("  crash_report.json    AFL crash report JSON file")
        print()
        print("Options:")
        print("  --total-args N       Total number of arguments binary expects (required)")
        print("  --use-hex            Use hex representation instead of printable")
        print("  --binary <binary>    Binary path")
        print("  --arg-pos N          Override argument position (auto-detect from filename)")
        print("  -h, --help           Show this help")
        print()
        print("Examples:")
        print("  # Auto-detect arg position from filename, 5 total args")
        print("  python3 generate_trace_from_json.py five_args_vuln_wrapper_arg2_crash.json --total-args 5")
        print()
        print("  # Specify argument position manually")
        print("  python3 generate_trace_from_json.py crash.json --total-args 3 --arg-pos 2")
        print()
        print("  # Use hex instead of printable")
        print("  python3 generate_trace_from_json.py crash.json --total-args 5 --use-hex")
        sys.exit(1)
    
    # Parse arguments
    folder = sys.argv[1]
    total_args = None
    use_hex = False
    arg_pos_override = None
    binary_path = None
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--total-args' and i + 1 < len(sys.argv):
            total_args = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--use-hex':
            use_hex = True
            i += 1
        elif sys.argv[i] == '--arg-pos' and i + 1 < len(sys.argv):
            arg_pos_override = int(sys.argv[i + 1])
            i += 1
        elif sys.argv[i] == '--binary' and i + 1 < len(sys.argv):
            binary_path = str(sys.argv[i+1])
            i += 2
        elif sys.argv[i] in ('-h', '--help'):
            print(main.__doc__)
            sys.exit(0)
        else:
            print(f"Unknown option: {sys.argv[i]}")
            sys.exit(1)
    
    # Validation
    if not os.path.isdir(folder):
        print(f"[!] JSON file folder not found: {folder}")
        sys.exit(1)
    
    if total_args is None:
        print("[!] Error: --total-args is required")
        print("    Specify how many arguments the binary expects")
        sys.exit(1)

    if binary_path is None:
        print("[!] Binary path --binary is required")
        sys.exit(1)

    files = os.listdir(folder)
    
    # Parse crash report
    print("="*70)
    print("AFL Crash Report → DynamoRIO Trace Generator")
    print("="*70)

    for f in files:
        json_path = f"{folder}/{f}"
        print(f"[*] Running {json_path}")
        print(json_path)
        print(f"[*] Parsing: {json_path}")
        crash_data = parse_crash_report(json_path)
        if not crash_data:
            sys.exit(1)
        
        print(f"[+] Binary: {crash_data['binary']}")
        print(f"[+] Input size: {crash_data['input_size']} bytes")
        print(f"[+] Crash signal: {crash_data['crash_signal']}")
        # Determine argument position
        if arg_pos_override:
            arg_position = arg_pos_override
            print(f"[+] Argument position: {arg_position} (manually specified)")
        else:
            arg_position = extract_arg_position(crash_data['binary'])
            if arg_position:
                print(f"[+] Argument position: {arg_position} (auto-detected from filename)")
            else:
                print("[!] Could not auto-detect argument position")
                print("    Use --arg-pos N to specify manually")
                sys.exit(1)
        
        # Validate position
        if arg_position < 1 or arg_position > total_args:
            print(f"[!] Invalid argument position: {arg_position}")
            print(f"    Must be between 1 and {total_args}")
            sys.exit(1)
        
        # Select input representation
        if use_hex:
            crash_input = crash_data['input_hex']
            print(f"[+] Using hex representation: {crash_input[:50]}...")
        else:
            crash_input = crash_data['input_printable']
            print(f"[+] Using printable representation: {crash_input[:50]}...")
        
        # Build argument list
        print(f"\n[*] Building argument list (total: {total_args} args):")
        args_list = build_argument_list(
            crash_input,
            arg_position,
            total_args,
            use_hex=False  # Always use string, not hex bytes
        )
        
        # Run with DynamoRIO
        print("\n" + "="*70)
        print("Running under DynamoRIO")
        print("="*70)
        
        result = run_with_dynamorio(binary_path, args_list)
        
        # Display results
        print("\n" + "="*70)
        print("Execution Results")
        print("="*70)
        print(f"Return code: {result['return_code']}")
        print(f"Crashed: {'Yes ✓' if result['crashed'] else 'No'}")
        
        if result['stdout']:
            print(f"\nStdout:\n{result['stdout'][:500]}")
        
        if result['stderr']:
            print(f"\nStderr:\n{result['stderr'][:500]}")
        
        # Find trace directory
        trace_dir = find_latest_trace_dir()
        
        if trace_dir:
            print(f"\n[+] Traces generated in: {trace_dir}/")
            
            # Find input.bytes
            for root, dirs, files in os.walk(trace_dir):
                if 'input.bytes' in files:
                    input_bytes_path = os.path.join(root, 'input.bytes')
                    print(f"[+] input.bytes found: {input_bytes_path}")
                    
                    # Generate commands
                    inner_dir, commands = generate_read_trace_commands(trace_dir)
                    
                    print("\n" + "="*70)
                    print("Next Steps")
                    print("="*70)
                    print("Run these commands to analyze the trace:")
                    print()
                    for cmd in commands:
                        print(f"  {cmd}")
                    print()
                    
                    # Create a convenience script
                    script_name = f"analyze_{os.path.basename(trace_dir)}.sh"
                    with open(script_name, 'w') as f:
                        f.write("#!/bin/bash\n")
                        f.write("# Auto-generated trace analysis script\n\n")
                        f.write("set -e\n\n")
                        for cmd in commands:
                            f.write(f"{cmd}\n")
                    
                    os.chmod(script_name, 0o755)
                    print(f"[+] Created convenience script: {script_name}")
                    print(f"    Run with: ./{script_name}")
                    
                    break
        else:
            print("\n[!] Warning: Could not find trace directory")
            print("    Check if DynamoRIO generated traces successfully")
        
        #sys.exit(0 if not result['crashed'] else 2)
        continue


if __name__ == '__main__':
    main()
