#!/usr/bin/env python3

import os
import sys
import subprocess
import json
import hashlib
import time
import signal
from pathlib import Path
import re
import argparse
from datetime import datetime

class AFLFuzzerAnalyzer:
    def __init__(self, binary, input_dir, output_dir, timeout=300, mode='qemu', analyze=True, actual_binary=None, report_filename='crash_report.json'):
        self.binary = Path(binary).resolve()
        self.input_dir = Path(input_dir).resolve()
        self.output_dir = Path(output_dir).resolve()
        self.timeout = timeout
        self.mode = mode
        self.analyze = analyze
        # NEW: Support for actual binary when using wrapper
        self.actual_binary = Path(actual_binary).resolve() if actual_binary else None
        self.report_filename = report_filename
        self.dynamorio_home = os.environ.get('DYNAMORIO_HOME')
        self.afl_fuzz = None
        self.crash_dir = None

        self.find_afl()

        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary}")
        if not self.input_dir.exists():
            raise FileNotFoundError(f"Input directory not found: {self.input_dir}")

    def find_afl(self):
        """Find AFL fuzzer"""
        possible_paths = [
            Path.home() / 'afl-dynamorio' / 'afl' / 'afl-fuzz',
            Path('/usr/local/bin/afl-fuzz'),
            Path('/usr/bin/afl-fuzz'),
        ]

        for path in possible_paths:
            if path.exists():
                self.afl_fuzz = path
                print(f"[+] Found AFL at: {self.afl_fuzz}")
                return

        try:
            result = subprocess.run(['which', 'afl-fuzz'], capture_output=True, text=True)
            if result.returncode == 0:
                self.afl_fuzz = Path(result.stdout.strip())
                print(f"[+] Found AFL at: {self.afl_fuzz}")
                return
        except:
            pass

        raise FileNotFoundError("AFL fuzzer (afl-fuzz) not found")

    def run_fuzzer(self):
        """Run AFL fuzzer"""
        print(f"\n{'='*70}")
        print(f"Starting AFL Fuzzing")
        print(f"{'='*70}")
        print(f"Binary:      {self.binary}")
        if self.actual_binary:
            print(f"Target:      {self.actual_binary}")
        print(f"Input dir:   {self.input_dir}")
        print(f"Output dir:  {self.output_dir}")
        print(f"Mode:        {self.mode}")
        print(f"Timeout:     {self.timeout} seconds")
        print(f"{'='*70}\n")

        env = os.environ.copy()
        env['AFL_SKIP_BIN_CHECK'] = '1'

        if self.mode == 'qemu':
            cmd = [
                str(self.afl_fuzz),
                '-Q',
                '-i', str(self.input_dir),
                '-o', str(self.output_dir),
                '--',
                str(self.binary),
                '@@'
            ]
        elif self.mode == 'gcc':
            cmd = [
                str(self.afl_fuzz),
                '-i', str(self.input_dir),
                '-o', str(self.output_dir),
                '--',
                str(self.binary),
                '@@'
            ]
        elif self.mode == 'dynamorio':
            if not self.dynamorio_home:
                raise ValueError("DYNAMORIO_HOME not set for DynamoRIO mode")

            drrun = Path(self.dynamorio_home) / 'bin64' / 'drrun'
            libafl = Path('/usr/local/lib/dynamorio/libafl-dynamorio.so')

            if not drrun.exists():
                raise FileNotFoundError(f"drrun not found at {drrun}")
            if not libafl.exists():
                raise FileNotFoundError(f"libafl-dynamorio.so not found at {libafl}")

            cmd = [
                str(self.afl_fuzz),
                '-n',
                '-m', 'none',
                '-t', '10000+',
                '-i', str(self.input_dir),
                '-o', str(self.output_dir),
                '--',
                str(drrun),
                '-c', str(libafl),
                '--',
                str(self.binary),
                '@@'
            ]
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

        print(f"[*] Running command: {' '.join(cmd)}\n")

        try:
            start_time = time.time()
            process = subprocess.Popen(cmd, env=env)

            time.sleep(self.timeout)

            print("\n[*] Timeout reached, stopping fuzzer...")
            process.send_signal(signal.SIGINT)
            time.sleep(2)

            if process.poll() is None:
                process.terminate()
                time.sleep(1)

            if process.poll() is None:
                process.kill()

            elapsed = time.time() - start_time
            print(f"[+] Fuzzing completed in {elapsed:.2f} seconds")

            self.crash_dir = self.output_dir / 'default' / 'crashes'
            if self.crash_dir.exists():
                crash_count = len(list(self.crash_dir.glob('id:*')))
                print(f"[+] Found {crash_count} unique crashes")
                return crash_count > 0
            else:
                print("[-] No crashes directory found")
                return False

        except KeyboardInterrupt:
            print("\n[!] Fuzzing interrupted by user")
            if process.poll() is None:
                process.terminate()
            return False
        except Exception as e:
            print(f"[!] Error during fuzzing: {e}")
            return False

    def get_crash_files(self):
        """Get all crash files"""
        if not self.crash_dir or not self.crash_dir.exists():
            return []

        crashes = []
        for crash_file in self.crash_dir.glob("id:*"):
            if crash_file.is_file() and crash_file.name != "README.txt":
                crashes.append(crash_file)
        return sorted(crashes)

    def read_crash_input(self, crash_file):
        """Read and analyze crash input"""
        with open(crash_file, 'rb') as f:
            data = f.read()

        return {
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'hex': data.hex(),
            'printable': ''.join(chr(b) if 32 <= b < 127 else '.' for b in data),
            'raw_bytes': list(data)
        }

    def run_with_gdb(self, crash_file):
        """Run crash with GDB - FIXED to analyze actual binary, not wrapper"""
        
        # Determine which binary to analyze with GDB
        target_binary = self.actual_binary if self.actual_binary else self.binary
        
        print(f"      [GDB] Analyzing: {target_binary}")
        
        # NEW: If using wrapper, we need to run the wrapper but attach GDB to the actual binary
        if self.actual_binary:
            # Method 1: Run wrapper, let it crash, analyze core dump
            # Method 2: Reproduce crash directly with actual binary
            # We'll use Method 2: reconstruct the command
            
            # Read the crash input
            with open(crash_file, 'rb') as f:
                crash_input = f.read()
            
            # For wrapper_arg1, the input becomes argument 1 of vulnbin
            # We need to pass it directly to vulnbin for GDB analysis
            gdb_script = f"""
set pagination off
set confirm off
set print pretty on
set disassembly-flavor intel
file {target_binary}
run {crash_input.decode('utf-8', errors='replace')} static_arg2 static_arg3 static_arg4 static_arg5 static_arg6 static_arg7 static_arg8
info program
bt full
info registers
x/40wx $rsp
x/20i $rip-40
quit
"""
        else:
            # Normal case: analyze the binary directly with file input
            gdb_script = f"""
set pagination off
set confirm off
set print pretty on
set disassembly-flavor intel
file {target_binary}
run {crash_file}
info program
bt full
info registers
x/40wx $rsp
x/20i $rip-40
quit
"""

        try:
            result = subprocess.run(
                ['gdb', '-batch'],
                input=gdb_script,
                capture_output=True,
                text=True,
                timeout=15
            )

            output = result.stdout + "\n" + result.stderr
            crash_test_output = self.test_crash_direct(crash_file)

            crash_info = {
                'gdb_output': output,
                'direct_test': crash_test_output,
                'signal': self.extract_signal(output),
                'signal_code': self.extract_signal_code(output),
                'fault_address': self.extract_fault_address(output),
                'backtrace': self.extract_backtrace(output),
                'backtrace_full': self.extract_backtrace_full(output),
                'registers': self.extract_registers(output),
                'instruction_pointer': self.extract_rip(output),
                'crashing_instruction': self.extract_crashing_instruction(output),
                'stack_dump': self.extract_stack_dump(output),
                'crash_reason': self.determine_crash_reason(output),
                'exploitability': self.assess_exploitability(output)
            }

            return crash_info
        except subprocess.TimeoutExpired:
            return {'error': 'GDB timeout', 'direct_test': self.test_crash_direct(crash_file)}
        except Exception as e:
            return {'error': str(e), 'direct_test': self.test_crash_direct(crash_file)}

    def test_crash_direct(self, crash_file):
        """Test crash without GDB"""
        try:
            subprocess.run(['bash', '-c', 'ulimit -c unlimited'], check=False)

            result = subprocess.run(
                [str(self.binary), str(crash_file)],
                capture_output=True,
                text=True,
                timeout=5
            )

            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'crashed': result.returncode < 0,
                'exit_signal': -result.returncode if result.returncode < 0 else None
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Timeout', 'crashed': True}
        except Exception as e:
            return {'error': str(e)}

    def run_with_dynamorio(self, crash_file):
        """Run crash with DynamoRIO"""
        if not self.dynamorio_home:
            return {'skipped': 'DynamoRIO not available'}

        drrun = Path(self.dynamorio_home) / 'bin64' / 'drrun'
        if not drrun.exists():
            return {'error': 'drrun not found'}

        try:
            result = subprocess.run(
                [str(drrun), '-t', 'drcov', '--', str(self.binary), str(crash_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            drcov_logs = list(Path('.').glob('drcov.*.log'))
            coverage_data = None
            if drcov_logs:
                latest_log = max(drcov_logs, key=os.path.getctime)
                with open(latest_log, 'r') as f:
                    coverage_data = f.read()
                latest_log.unlink()

            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'coverage_available': coverage_data is not None,
                'coverage_data': coverage_data[:2000] if coverage_data else None
            }
        except subprocess.TimeoutExpired:
            return {'error': 'DynamoRIO timeout'}
        except Exception as e:
            return {'error': str(e)}

    def extract_signal(self, gdb_output):
        """Extract signal from GDB output"""
        patterns = [
            r'Program received signal (\w+)',
            r'Signal\s+(\w+)',
            r'Fatal signal (\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, gdb_output)
            if match:
                return match.group(1)

        if 'exited with code' in gdb_output:
            return 'EXIT'

        return None

    def extract_signal_code(self, gdb_output):
        """Extract signal code/number"""
        match = re.search(r'signal (\d+)', gdb_output, re.IGNORECASE)
        return match.group(1) if match else None

    def extract_fault_address(self, gdb_output):
        """Extract fault address"""
        patterns = [
            r'at address (0x[0-9a-f]+)',
            r'fault address (0x[0-9a-f]+)',
            r'Cannot access memory at address (0x[0-9a-f]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, gdb_output)
            if match:
                return match.group(1)

        return None

    def extract_backtrace(self, gdb_output):
        """Extract backtrace"""
        bt_lines = []
        for line in gdb_output.split('\n'):
            if re.match(r'^#\d+', line.strip()):
                bt_lines.append(line.strip())
        return bt_lines

    def extract_backtrace_full(self, gdb_output):
        """Extract full backtrace with local variables"""
        in_bt = False
        bt_full = []

        for line in gdb_output.split('\n'):
            if re.match(r'^#\d+', line.strip()):
                in_bt = True
            if in_bt:
                bt_full.append(line)
                if line.strip() == '' and len(bt_full) > 20:
                    break

        return '\n'.join(bt_full)

    def extract_registers(self, gdb_output):
        """Extract registers"""
        registers = {}

        lines = gdb_output.split('\n')
        for i, line in enumerate(lines):
            match = re.match(r'(\w+)\s+(0x[0-9a-f]+)', line.strip())
            if match and len(match.group(1)) <= 5:
                registers[match.group(1)] = match.group(2)

        return registers

    def extract_rip(self, gdb_output):
        """Extract instruction pointer"""
        patterns = [
            r'rip\s+(0x[0-9a-f]+)',
            r'pc\s+(0x[0-9a-f]+)',
            r'eip\s+(0x[0-9a-f]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, gdb_output, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def extract_crashing_instruction(self, gdb_output):
        """Extract the crashing instruction"""
        lines = gdb_output.split('\n')
        for line in lines:
            if '=>' in line and '0x' in line:
                return line.strip()
        return None

    def extract_stack_dump(self, gdb_output):
        """Extract stack memory dump"""
        stack_lines = []
        in_stack = False

        for line in gdb_output.split('\n'):
            if 'x/40wx $rsp' in line or 'x/40wx $rbp' in line:
                in_stack = True
            elif in_stack:
                if re.match(r'0x[0-9a-f]+:', line):
                    stack_lines.append(line.strip())
                elif line.strip() and not line.startswith('0x'):
                    break

        return stack_lines

    def determine_crash_reason(self, gdb_output):
        """Determine the likely reason for crash"""
        reasons = []

        if 'stack overflow' in gdb_output.lower():
            reasons.append("Stack overflow detected")

        if 'heap' in gdb_output.lower() and ('corrupt' in gdb_output.lower() or 'invalid' in gdb_output.lower()):
            reasons.append("Heap corruption detected")

        if 'double free' in gdb_output.lower():
            reasons.append("Double free detected")

        if 'use after free' in gdb_output.lower():
            reasons.append("Use-after-free detected")

        if 'Cannot access memory' in gdb_output:
            reasons.append("Invalid memory access")

        if 'SIGSEGV' in gdb_output or 'Segmentation fault' in gdb_output:
            reasons.append("Segmentation fault - invalid memory access")

        if 'SIGILL' in gdb_output:
            reasons.append("Illegal instruction - possible code execution")

        if 'SIGABRT' in gdb_output:
            reasons.append("Abort signal - assertion failure or corruption")

        return reasons if reasons else ["Unknown crash reason"]

    def assess_exploitability(self, gdb_output):
        """Assess if crash might be exploitable"""
        score = 0
        indicators = []

        if 'SIGILL' in gdb_output:
            score += 3
            indicators.append("Illegal instruction (possible PC control)")

        rip = self.extract_rip(gdb_output)
        if rip:
            try:
                addr = int(rip, 16)
                if 0x4141414100000000 <= addr <= 0x4242424300000000:
                    score += 4
                    indicators.append(f"RIP points to ASCII-like value: {rip}")
                elif addr < 0x1000:
                    score += 2
                    indicators.append(f"RIP points to low memory: {rip}")
            except:
                pass

        fault = self.extract_fault_address(gdb_output)
        if fault:
            try:
                addr = int(fault, 16)
                if 0x4141414100000000 <= addr <= 0x4242424300000000:
                    score += 3
                    indicators.append(f"Fault at ASCII-like address: {fault}")
            except:
                pass

        bt = ' '.join(self.extract_backtrace(gdb_output))
        vuln_funcs = ['strcpy', 'sprintf', 'gets', 'scanf']
        for func in vuln_funcs:
            if func in bt:
                score += 2
                indicators.append(f"Crash in vulnerable function: {func}")
                break

        if score >= 5:
            return {"level": "HIGH", "score": score, "indicators": indicators}
        elif score >= 3:
            return {"level": "MEDIUM", "score": score, "indicators": indicators}
        elif score >= 1:
            return {"level": "LOW", "score": score, "indicators": indicators}
        else:
            return {"level": "UNKNOWN", "score": 0, "indicators": ["Insufficient data"]}

    def is_input_dependent(self, crash_info, input_data):
        """Determine if crash is input-dependent"""
        score = 0
        reasons = []

        direct = crash_info.get('direct_test', {})
        if direct.get('crashed'):
            score += 2
            reasons.append(f"Program crashes when run with this input (exit signal: {direct.get('exit_signal', 'unknown')})")

        bt = ' '.join(crash_info.get('backtrace', []))
        vuln_funcs = ['strcpy', 'memcpy', 'sprintf', 'gets', 'fgets', 'strcat', 'scanf', 'read', 'fread']
        for func in vuln_funcs:
            if func in bt.lower():
                score += 3
                reasons.append(f"Crash in input-handling function: {func}")
                break

        signal = crash_info.get('signal')
        if signal == 'SIGSEGV' or signal == '11':
            score += 2
            reasons.append("Segmentation fault (memory corruption)")
        elif signal == 'SIGABRT' or signal == '6':
            score += 1
            reasons.append("Abort signal")
        elif signal == 'SIGILL' or signal == '4':
            score += 3
            reasons.append("Illegal instruction (possible code execution)")
        elif signal == 'SIGFPE' or signal == '8':
            score += 1
            reasons.append("Floating point exception")

        crash_reasons = crash_info.get('crash_reason', [])
        for reason in crash_reasons:
            if 'overflow' in reason.lower():
                score += 2
                reasons.append(reason)

        fault_addr = crash_info.get('fault_address')
        if fault_addr:
            try:
                addr_int = int(fault_addr, 16)
                if 0x20202020 <= addr_int <= 0x7e7e7e7e7e7e7e7e:
                    score += 3
                    reasons.append(f"Fault address contains ASCII data: {fault_addr}")
                elif addr_int != 0:
                    score += 1
                    reasons.append(f"Non-null fault address: {fault_addr}")
            except:
                pass

        exploit = crash_info.get('exploitability', {})
        if exploit.get('level') in ['HIGH', 'MEDIUM']:
            score += 2
            reasons.append(f"Exploitability: {exploit.get('level')} - {', '.join(exploit.get('indicators', []))}")

        registers = crash_info.get('registers', {})
        input_bytes = input_data.get('raw_bytes', [])

        if len(input_bytes) >= 4:
            for reg, value in registers.items():
                try:
                    val_int = int(value, 16)
                    val_bytes = val_int.to_bytes(8, 'little', signed=False)

                    for i in range(len(input_bytes) - 3):
                        for j in range(5):
                            if input_bytes[i:i+4] == list(val_bytes[j:j+4]):
                                score += 3
                                reasons.append(f"Register {reg} contains input data: {value}")
                                break
                except:
                    pass

        if input_data['size'] > 16:
            score += 1
            reasons.append(f"Large input size: {input_data['size']} bytes")

        return {
            'is_input_dependent': score >= 3,
            'confidence_score': score,
            'max_score': 20,
            'confidence_percent': min(100, int((score / 20) * 100)),
            'reasons': reasons
        }

    def analyze_crash(self, crash_file):
        """Analyze a single crash"""
        print(f"  [*] Analyzing: {crash_file.name}")

        input_data = self.read_crash_input(crash_file)
        gdb_analysis = self.run_with_gdb(crash_file)

        crash_data = {
            'filename': crash_file.name,
            'filepath': str(crash_file),
            'timestamp': datetime.now().isoformat(),
            'input': input_data,
            'gdb_analysis': gdb_analysis
        }

        if self.mode == 'dynamorio' or self.dynamorio_home:
            crash_data['dynamorio_analysis'] = self.run_with_dynamorio(crash_file)

        dependency = self.is_input_dependent(gdb_analysis, input_data)
        crash_data['input_dependency'] = dependency

        print(f"      Signal: {gdb_analysis.get('signal', 'Unknown')}")
        print(f"      Crash Reason: {', '.join(gdb_analysis.get('crash_reason', ['Unknown']))}")
        print(f"      Exploitability: {gdb_analysis.get('exploitability', {}).get('level', 'Unknown')}")
        print(f"      Input-dependent: {dependency['is_input_dependent']} "
              f"(confidence: {dependency['confidence_percent']}%)")

        return crash_data

    def analyze_crashes(self):
        """Analyze all crashes"""
        print(f"\n{'='*70}")
        print("Analyzing Crashes")
        print(f"{'='*70}\n")

        crash_files = self.get_crash_files()
        if not crash_files:
            print("[-] No crashes to analyze")
            return []

        print(f"[+] Found {len(crash_files)} crashes to analyze\n")

        results = []
        for crash_file in crash_files:
            try:
                result = self.analyze_crash(crash_file)
                results.append(result)
            except Exception as e:
                print(f"  [!] Error analyzing {crash_file.name}: {e}")
                import traceback
                traceback.print_exc()
                results.append({
                    'filename': crash_file.name,
                    'error': str(e)
                })

        return results

    def save_report(self, results, filename='crash_report.json'):
        """Save analysis results to JSON"""
        report = {
            'metadata': {
                'binary': str(self.binary),
                'actual_binary': str(self.actual_binary) if self.actual_binary else None,
                'input_dir': str(self.input_dir),
                'output_dir': str(self.output_dir),
                'mode': self.mode,
                'timeout': self.timeout,
                'timestamp': datetime.now().isoformat(),
                'total_crashes': len(results)
            },
            'crashes': results
        }

        report_path = Path(filename)
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to: {report_path.resolve()}")
        return report_path

    def print_summary(self, results):
        """Print summary of results"""
        print(f"\n{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}\n")

        total = len(results)
        input_dependent = sum(1 for r in results
                            if r.get('input_dependency', {}).get('is_input_dependent'))

        print(f"Total crashes analyzed:     {total}")
        print(f"Input-dependent crashes:    {input_dependent}")
        print(f"Non-input-dependent:        {total - input_dependent}")

        signals = {}
        for r in results:
            sig = r.get('gdb_analysis', {}).get('signal')
            if sig is None:
                sig = 'Unknown'
            signals[sig] = signals.get(sig, 0) + 1

        print(f"\nCrashes by signal:")
        for sig, count in sorted(signals.items(), key=lambda x: x[1], reverse=True):
            print(f"  {sig:15s}: {count}")

        print(f"\nExploitability Assessment:")
        exploit_levels = {}
        for r in results:
            level = r.get('gdb_analysis', {}).get('exploitability', {}).get('level', 'Unknown')
            exploit_levels[level] = exploit_levels.get(level, 0) + 1

        for level, count in sorted(exploit_levels.items(), key=lambda x: x[1], reverse=True):
            print(f"  {level:15s}: {count}")

        if input_dependent > 0:
            print(f"\nInput-dependent crashes:")
            for r in results:
                if r.get('input_dependency', {}).get('is_input_dependent'):
                    conf = r['input_dependency']['confidence_percent']
                    exploit = r.get('gdb_analysis', {}).get('exploitability', {}).get('level', 'Unknown')
                    print(f"  {r['filename']:50s} (confidence: {conf}%, exploitability: {exploit})")

        print(f"\n{'='*70}")
        print("DETAILED CRASH INFORMATION")
        print(f"{'='*70}")

        for r in results:
            print(f"\n{'─'*70}")
            print(f"Crash: {r['filename']}")
            print(f"{'─'*70}")

            gdb = r.get('gdb_analysis', {})
            print(f"  Signal:           {gdb.get('signal', 'Unknown')}")
            print(f"  Fault Address:    {gdb.get('fault_address', 'N/A')}")
            print(f"  Crash Reasons:    {', '.join(gdb.get('crash_reason', ['Unknown']))}")

            exploit = gdb.get('exploitability', {})
            print(f"  Exploitability:   {exploit.get('level', 'Unknown')} (score: {exploit.get('score', 0)})")
            if exploit.get('indicators'):
                for ind in exploit['indicators']:
                    print(f"    - {ind}")

            print(f"\n  Input Information:")
            inp = r.get('input', {})
            print(f"    Size:           {inp.get('size', 0)} bytes")
            print(f"    Printable:      {inp.get('printable', '')[:60]}")
            print(f"    Hex (first 64): {inp.get('hex', '')[:64]}")

            dep = r.get('input_dependency', {})
            print(f"\n  Input Dependency:")
            print(f"    Verdict:        {dep.get('is_input_dependent', False)}")
            print(f"    Confidence:     {dep.get('confidence_percent', 0)}%")
            print(f"    Score:          {dep.get('confidence_score', 0)}/{dep.get('max_score', 0)}")

            if dep.get('reasons'):
                print(f"    Evidence:")
                for reason in dep['reasons']:
                    print(f"      ✓ {reason}")

            bt = gdb.get('backtrace', [])
            if bt:
                print(f"\n  Backtrace (top 5):")
                for line in bt[:5]:
                    print(f"    {line}")

            regs = gdb.get('registers', {})
            if regs:
                print(f"\n  Key Registers:")
                for reg in ['rip', 'rsp', 'rbp', 'rax', 'rdi', 'rsi']:
                    if reg in regs:
                        print(f"    {reg:4s} = {regs[reg]}")

    def run(self):
        """Run complete fuzzing and analysis pipeline"""
        try:
            has_crashes = self.run_fuzzer()

            if not has_crashes:
                print("\n[-] No crashes found during fuzzing")
                return None

            if self.analyze:
                results = self.analyze_crashes()
                report_path = self.save_report(results, filename=self.report_filename)
                self.print_summary(results)
                return results
            else:
                print("\n[*] Analysis skipped (use --analyze to enable)")
                return None

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            return None
        except Exception as e:
            print(f"\n[!] Error: {e}")
            import traceback
            traceback.print_exc()
            return None

def main():
    parser = argparse.ArgumentParser(
        description='AFL fuzzer and crash analyzer with wrapper support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic fuzzing
  %(prog)s -b ./vuln -i seeds -o findings -t 300

  # Fuzzing with wrapper (analyze actual binary, not wrapper)
  %(prog)s -b ./wrapper_arg1 -i seeds -o findings -t 120 --actual-binary ./bins/vulnbin
        '''
    )

    parser.add_argument('-b', '--binary', required=True,
                        help='Path to target binary (or wrapper)')
    parser.add_argument('-i', '--input', required=True,
                        help='Input directory with seed files')
    parser.add_argument('-o', '--output', required=True,
                        help='Output directory for AFL results')
    parser.add_argument('-t', '--timeout', type=int, default=300,
                        help='Fuzzing timeout in seconds (default: 300)')
    parser.add_argument('-m', '--mode', choices=['qemu', 'gcc', 'dynamorio'],
                        default='qemu',
                        help='Fuzzing mode (default: qemu)')
    parser.add_argument('--actual-binary',
                        help='Actual binary to analyze (when using wrapper)')
    parser.add_argument('--no-analyze', dest='analyze', action='store_false',
                        help='Skip crash analysis')
    parser.add_argument('-r', '--report', default='crash_report.json',
                        help='Output report filename (default: crash_report.json)')

    args = parser.parse_args()

    fuzzer = AFLFuzzerAnalyzer(
        binary=args.binary,
        input_dir=args.input,
        output_dir=args.output,
        timeout=args.timeout,
        mode=args.mode,
        analyze=args.analyze,
        actual_binary=args.actual_binary,
        report_filename=args.report
    )

    fuzzer.run()

if __name__ == '__main__':
    main()
