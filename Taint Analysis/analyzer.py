#!/usr/bin/env python3
import sys
import os
import re
import subprocess
from collections import defaultdict
import tempfile

class CompleteAnalyzer:
    def __init__(self, binary, args, input_index=1):
        self.binary = binary
        self.args = args
        self.input_index = input_index
        
        # Extract input data
        if 0 <= input_index < len(args):
            input_str = args[input_index]
            self.input_data = input_str.encode() if isinstance(input_str, str) else input_str
        else:
            self.input_data = b''
        
        self.gdb_output = None
        self.crashed = False
        self.stack_data = None
    
    def test_crash(self):
        """Test if program crashes"""
        
        print("="*80)
        print("COMPLETE VULNERABILITY ANALYZER")
        print("="*80)
        print()
        
        print("[PHASE 1] CRASH TEST")
        print("-" * 80)
        
        print(f"Binary: {self.binary}")
        print(f"Arguments: {self.args}")
        print(f"Input (arg {self.input_index}): {len(self.input_data)} bytes")
        print(f"  Hex: {self.input_data[:32].hex()}")
        print(f"  ASCII: {self.input_data[:50].decode('latin-1', errors='replace')}")
        print()
        
        try:
            result = subprocess.run(
                [self.binary] + self.args,
                capture_output=True,
                timeout=5
            )
            
            exit_code = result.returncode
            
            if exit_code < 0:
                signal_num = -exit_code
                self.crashed = True
                print(f"✓ Program crashed with signal {signal_num}")
                if signal_num == 11:
                    print("  Signal 11 = SIGSEGV (Segmentation fault)")
                print()
                return True
            else:
                print(f"✗ Program exited normally (exit code {exit_code})")
                print()
                return False
                
        except subprocess.TimeoutExpired:
            print("✗ Program timed out")
            print()
            return False
    
    def analyze_with_gdb(self):
        """Analyze crash with GDB"""
        
        print("[PHASE 2] GDB ANALYSIS")
        print("-" * 80)
        
        # Create GDB script
        gdb_script = f"""
set pagination off
set confirm off
set disable-randomization on

file {self.binary}
set args {' '.join(f'"{arg}"' for arg in self.args)}

run

printf "\\n=== CRASHED ===\\n"
printf "RIP: "
print/x $rip
printf "RSP: "
print/x $rsp
printf "RBP: "
print/x $rbp

printf "\\n=== ALL REGISTERS ===\\n"
info registers all

printf "\\n=== RIP BYTES ===\\n"
x/8bx $rip

printf "\\n=== STACK QWORDS ===\\n"
x/32xg $rsp

printf "\\n=== RAW STACK BYTES ===\\n"
x/128xb $rsp

printf "\\n=== DISASSEMBLY ===\\n"
x/10i $rip-32

quit
"""
        
        # Write and run script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
            f.write(gdb_script)
            script_path = f.name
        
        try:
            result = subprocess.run(
                ['gdb', '--batch', '--command', script_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            self.gdb_output = result.stdout
            
            # Save to file
            with open('crash_analysis.log', 'w') as f:
                f.write(self.gdb_output)
            
            print("✓ GDB analysis complete")
            print("  Log saved to: crash_analysis.log")
            print()
            
        finally:
            os.unlink(script_path)
    
    def parse_and_analyze(self):
        """Parse GDB output and provide intelligent analysis"""
        
        if not self.gdb_output:
            print("No GDB output to analyze")
            return
        
        print("="*80)
        print("INTELLIGENT ANALYSIS")
        print("="*80)
        print()
        
        # Extract registers
        registers = {}
        
        # Find register section
        reg_patterns = {
            'RIP': r'rip\s+0x([0-9a-f]+)',
            'RSP': r'rsp\s+0x([0-9a-f]+)',
            'RBP': r'rbp\s+0x([0-9a-f]+)',
            'RAX': r'rax\s+0x([0-9a-f]+)',
            'RDI': r'rdi\s+0x([0-9a-f]+)',
            'RSI': r'rsi\s+0x([0-9a-f]+)',
        }
        
        for reg_name, pattern in reg_patterns.items():
            match = re.search(pattern, self.gdb_output, re.I)
            if match:
                registers[reg_name] = int(match.group(1), 16)
        
        # Extract stack bytes
        stack_section = re.search(r'=== RAW STACK BYTES ===(.*?)(?:===|$)', self.gdb_output, re.DOTALL)
        if stack_section:
            stack_lines = stack_section.group(1)
            
            stack_bytes = []
            for line in stack_lines.split('\n'):
                hex_vals = re.findall(r'0x([0-9a-f]{2})', line, re.I)
                for hv in hex_vals:
                    stack_bytes.append(int(hv, 16))
            
            self.stack_data = bytes(stack_bytes[:128])
        
        # Analysis 1: Crash Location
        print("[1] CRASH LOCATION")
        print("-" * 80)
        
        crash_match = re.search(r'0x([0-9a-f]+)[^:]*<([^>]+)>.*?:\s+(\w+)', self.gdb_output)
        if crash_match:
            crash_addr = crash_match.group(1)
            crash_func = crash_match.group(2)
            crash_instr = crash_match.group(3)
            
            print(f"Function: {crash_func}")
            print(f"Address: 0x{crash_addr}")
            print(f"Instruction: {crash_instr}")
            
            if crash_instr.lower() == 'ret':
                print()
                print("🎯 CRASH AT RET INSTRUCTION!")
                print("   The return address was corrupted.")
                print("   When the function tried to return, it jumped to invalid address.")
        
        print()
        
        # Analysis 2: Register State
        print("[2] REGISTER STATE")
        print("-" * 80)
        
        for reg in ['RIP', 'RSP', 'RBP', 'RAX', 'RDI', 'RSI']:
            if reg in registers:
                val = registers[reg]
                print(f"{reg}: 0x{val:016x}", end='')
                
                # Check for patterns
                val_bytes = val.to_bytes(8, 'little')
                
                if reg == 'RBP' and val_bytes in self.input_data:
                    input_offset = self.input_data.index(val_bytes)
                    print(f" 🎯 FROM INPUT[{input_offset}]")
                    print(f"     Contains: {val_bytes.decode('latin-1', errors='replace')}")
                elif reg == 'RSP' and self.stack_data and self.stack_data[:8] in self.input_data:
                    print(f" 🎯 Points to input data on stack")
                else:
                    print()
        
        print()
        
        # Analysis 3: Stack Analysis
        print("[3] STACK CONTENTS")
        print("-" * 80)
        
        if self.stack_data:
            print("Stack dump (64 bytes from RSP):")
            print()
            
            for i in range(0, min(64, len(self.stack_data)), 16):
                chunk = self.stack_data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                
                marker = ""
                if i == 0:
                    marker = " ← Return address"
                elif i == 8:
                    marker = " ← Saved RBP"
                
                print(f"  +{i:3d}: {hex_str:48s} | {ascii_str:16s}{marker}")
            
            print()
            
            # Analyze return address
            ret_addr = self.stack_data[0:8]
            ret_addr_int = int.from_bytes(ret_addr, 'little')
            
            print("Return address analysis:")
            print(f"  Value: 0x{ret_addr_int:016x}")
            print(f"  Bytes: {ret_addr.hex()}")
            
            if ret_addr in self.input_data:
                offset = self.input_data.index(ret_addr)
                print(f"  🎯 EXACT MATCH to input at offset {offset}")
                print(f"  ASCII: {ret_addr.decode('latin-1', errors='replace')}")
                print()
                print(f"  Buffer size: ~{offset} bytes")
            elif any(ret_addr[i:i+4] in self.input_data for i in range(5)):
                print(f"  ⚠️  PARTIAL MATCH to input")
            else:
                print(f"  ✗ No direct match to input")
            
            print()
            
            # Analyze saved RBP
            saved_rbp = self.stack_data[8:16]
            saved_rbp_int = int.from_bytes(saved_rbp, 'little')
            
            print("Saved RBP analysis:")
            print(f"  Value: 0x{saved_rbp_int:016x}")
            print(f"  Bytes: {saved_rbp.hex()}")
            
            if saved_rbp in self.input_data:
                offset = self.input_data.index(saved_rbp)
                print(f"  🎯 EXACT MATCH to input at offset {offset}")
                print(f"  ASCII: {saved_rbp.decode('latin-1', errors='replace')}")
            
            print()
        
        # Analysis 4: Input Pattern Tracking
        print("[4] INPUT PATTERN TRACKING")
        print("-" * 80)
        
        if self.stack_data:
            matches = []
            
            # Find all matches
            for length in [8, 4, 2]:
                for i in range(len(self.stack_data) - length + 1):
                    chunk = self.stack_data[i:i+length]
                    
                    if chunk in self.input_data:
                        input_offset = self.input_data.index(chunk)
                        
                        # Check if not already covered
                        covered = False
                        for m in matches:
                            if m['stack_offset'] <= i < m['stack_offset'] + m['length']:
                                covered = True
                                break
                        
                        if not covered:
                            matches.append({
                                'stack_offset': i,
                                'input_offset': input_offset,
                                'length': length,
                                'bytes': chunk
                            })
            
            if matches:
                print(f"Found {len(matches)} regions with input data:")
                print()
                
                for i, m in enumerate(sorted(matches, key=lambda x: x['stack_offset'])[:15], 1):
                    hex_str = m['bytes'].hex()
                    ascii_str = m['bytes'].decode('latin-1', errors='replace')
                    print(f"  [{i:2d}] Stack +{m['stack_offset']:3d} ({m['length']:2d}b): {hex_str:16s} '{ascii_str:8s}' <- input[{m['input_offset']}]")
                
                print()
                
                # Critical locations
                print("Critical locations:")
                for offset, desc in [(0, "Return address"), (8, "Saved RBP"), (16, "Stack data")]:
                    if offset < len(self.stack_data):
                        chunk = self.stack_data[offset:offset+8]
                        
                        found = False
                        for m in matches:
                            if m['stack_offset'] <= offset < m['stack_offset'] + m['length']:
                                input_pos = m['input_offset'] + (offset - m['stack_offset'])
                                print(f"  {desc:20s}: {chunk.hex():16s} 🎯 FROM INPUT[{input_pos}]")
                                found = True
                                break
                        
                        if not found:
                            print(f"  {desc:20s}: {chunk.hex():16s}")
            else:
                print("✗ No input pattern found on stack")
            
            print()
        
        # Analysis 5: Vulnerability Assessment
        print("="*80)
        print("VULNERABILITY ASSESSMENT")
        print("="*80)
        print()
        
        confidence = 0
        evidence = []
        
        # Check crash type
        if 'ret' in self.gdb_output.lower():
            evidence.append("✓ Crashed at RET instruction")
            confidence += 30
        
        # Check if return address contains input
        if self.stack_data and self.stack_data[:8] in self.input_data:
            evidence.append("✓ Return address contains input bytes")
            confidence += 40
        
        # Check if saved RBP contains input
        if self.stack_data and len(self.stack_data) >= 16 and self.stack_data[8:16] in self.input_data:
            evidence.append("✓ Saved RBP contains input bytes")
            confidence += 20
        
        # Check for strcpy
        if 'strcpy' in self.gdb_output:
            evidence.append("✓ Uses strcpy() without bounds checking")
            confidence += 10
        
        print(f"Vulnerability Type: Stack Buffer Overflow")
        print(f"Confidence: {confidence}%")
        print()
        
        if evidence:
            print("Evidence:")
            for e in evidence:
                print(f"  {e}")
            print()
        
        if confidence >= 70:
            print("✅ EXPLOITABLE - HIGH CONFIDENCE")
            print()
            print("Attack Flow:")
            print("  1. Input copied to stack buffer via strcpy()")
            print("  2. Buffer overflow overwrites saved RBP and return address")
            print("  3. Function returns to attacker-controlled address")
            print("  4. Code execution achieved")
            print()
            
            if self.stack_data and self.stack_data[:8] in self.input_data:
                offset = self.input_data.index(self.stack_data[:8])
                print(f"Exploitation Details:")
                print(f"  Buffer size: ~{offset} bytes")
                print(f"  Offset to return address: {offset}")
                print(f"  Payload format: [padding({offset})][fake_rip(8)][shellcode]")
                print()
        elif confidence >= 40:
            print("⚠️  LIKELY EXPLOITABLE")
            print("   Further analysis needed")
            print()
        else:
            print("? UNCLEAR")
            print("   Manual analysis required")
            print()
        
        # Next steps
        print("Next Steps:")
        print("  1. Find exact buffer size with cyclic pattern")
        print("  2. Check security protections (checksec)")
        print("  3. Craft exploit payload")
        print("  4. Test with controlled RIP")
        print()
    
    def run(self):
        """Run complete analysis"""
        
        # Phase 1: Test crash
        if not self.test_crash():
            print("⚠️  WARNING: Program did not crash")
            print("Continuing with GDB analysis anyway...")
            print()
        
        # Phase 2: GDB analysis
        self.analyze_with_gdb()
        
        # Phase 3: Intelligent parsing
        self.parse_and_analyze()
        
        print("="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)
        print()
        print("Full GDB output saved to: crash_analysis.log")
        print()

class SizeBasedAnalyzer:
    def __init__(self, trace_dir, arg_index=2):
        self.trace_dir = trace_dir
        self.arg_index = arg_index

        self.input_bytes = None
        self.all_args = []
        self.memory_writes = []
        self.total_instructions = 0

    def load_input(self):
        """Load input from input.bytes"""

        print("="*80)
        print("SIZE-BASED OVERFLOW ANALYZER")
        print("Works without byte values in trace")
        print("="*80)
        print()

        input_path = os.path.join(self.trace_dir, 'input.bytes')

        if not os.path.isfile(input_path):
            print(f"[!] Error: input.bytes not found")
            return False

        with open(input_path, 'rb') as f:
            data = f.read()[32:]  # Skip metadata

        # Parse argv
        args = []
        pos = 0
        while pos < len(data):
            null_pos = data.find(b'\x00', pos)
            if null_pos == -1:
                break
            if len(data[pos:null_pos]) > 0:
                args.append(data[pos:null_pos])
            pos = null_pos + 1

        self.all_args = args

        if 0 <= self.arg_index < len(args):
            self.input_bytes = args[self.arg_index]
        else:
            print(f"[!] Invalid arg index")
            return False

        print("[*] INPUT ANALYSIS")
        print("-" * 80)
        print(f"Arguments: {len(args)}")
        for i, arg in enumerate(args[:8]):
            marker = " ← ANALYZING" if i == self.arg_index else ""
            print(f"  argv[{i}]: {arg[:50]}{marker}")

        print()
        print(f"Selected: argv[{self.arg_index}] = {len(self.input_bytes)} bytes")
        print(f"  Hex: {self.input_bytes[:32].hex()}")
        print(f"  ASCII: {self.input_bytes[:50].decode('latin-1', errors='replace')}")
        print()

        return True

    def generate_trace(self):
        """Generate memory trace"""

        print("[*] GENERATING MEMORY TRACE")
        print("-" * 80)

        try:
            result = subprocess.run(
                ['read_trace', '-m', self.trace_dir],
                capture_output=True,
                text=True,
                timeout=120
            )

            #if result.returncode != 0:
            #    print(f"[!] read_trace failed")
            #    return None

            print(f"✓ Generated: {len(result.stdout):,} bytes")
            print()

            return result.stdout

        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def parse_writes(self, trace):
        """Parse memory writes"""

        print("[*] PARSING WRITES")
        print("-" * 80)

        writes = []
        lines = trace.split('\n')
        current_instr = 0

        for line in lines:
            instr_match = re.match(r'\[(\d+)\]', line)
            if instr_match:
                current_instr = int(instr_match.group(1))
                self.total_instructions = max(self.total_instructions, current_instr)

            if 'Memory Write:' in line:
                addr_match = re.search(r'@\s+0x([0-9a-f]+)', line)
                size_match = re.search(r'Memory Write:\s*(\d+)\s*bytes', line)

                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    size = int(size_match.group(1)) if size_match else 1

                    # Stack only
                    if 0x7ff000000000 <= addr < 0x800000000000:
                        writes.append({
                            'instr': current_instr,
                            'addr': addr,
                            'size': size
                        })

        self.memory_writes = writes

        print(f"✓ Parsed {len(writes):,} stack writes")
        print(f"✓ Instructions: {self.total_instructions:,}")
        print()

        return writes

    def find_overflow_candidates(self):
        """Find overflow candidates based on size and pattern"""

        print("[*] CANDIDATE ANALYSIS")
        print("-" * 80)
        print("Looking for overflow patterns...")
        print()

        input_size = len(self.input_bytes)

        # Group consecutive writes
        groups = []
        current = []

        for write in sorted(self.memory_writes, key=lambda w: (w['addr'], w['instr'])):
            if not current:
                current = [write]
            else:
                last = current[-1]
                addr_diff = abs(write['addr'] - last['addr'])
                instr_diff = abs(write['instr'] - last['instr'])

                if addr_diff < 100 and instr_diff < 2000:
                    current.append(write)
                else:
                    if len(current) >= 8:
                        groups.append(current)
                    current = [write]

        if len(current) >= 8:
            groups.append(current)

        print(f"Found {len(groups)} write groups")
        print()

        # Score each group
        scored = []

        for group in groups:
            addrs = [w['addr'] for w in group]
            instrs = [w['instr'] for w in group]
            sizes = [w['size'] for w in group]

            min_addr = min(addrs)
            max_addr = max(addrs)
            span = max_addr - min_addr + max(sizes)
            total_bytes = sum(sizes)

            score = 0
            evidence = []

            # SIZE CORRELATION (most important without byte values!)
            size_diff = abs(span - input_size)
            if size_diff <= 1:
                score += 100
                evidence.append(f"🎯 EXACT SPAN MATCH: {span} ≈ {input_size}")
            elif size_diff <= 3:
                score += 70
                evidence.append(f"🎯 SPAN CLOSE: {span} ≈ {input_size} (diff: {size_diff})")
            elif size_diff <= 8:
                score += 40
                evidence.append(f"✓ Span similar: {span} vs {input_size} (diff: {size_diff})")

            # Check total bytes written
            bytes_diff = abs(total_bytes - input_size)
            if bytes_diff <= 1:
                score += 50
                evidence.append(f"🎯 TOTAL BYTES MATCH: {total_bytes} ≈ {input_size}")
            elif bytes_diff <= 5:
                score += 30
                evidence.append(f"✓ Total bytes close: {total_bytes} ≈ {input_size}")

            # TIGHT LOOP (strcpy pattern)
            instr_span = max(instrs) - min(instrs)
            instr_per_write = instr_span / len(group) if group else 1000
            if instr_per_write < 5:
                score += 30
                evidence.append(f"🎯 TIGHT LOOP: {instr_per_write:.1f} instr/write (strcpy!)")
            elif instr_per_write < 10:
                score += 15
                evidence.append(f"✓ Copy pattern: {instr_per_write:.1f} instr/write")

            # MANY WRITES (large copy)
            if len(group) >= 30:
                score += 20
                evidence.append(f"✓ Many writes: {len(group)}")
            elif len(group) >= 20:
                score += 10

            # EXECUTION PHASE (early = vulnerable function)
            phase = (min(instrs) / self.total_instructions * 100) if self.total_instructions else 50
            if phase < 15:
                score += 15
                evidence.append(f"✓ Early execution: {phase:.1f}%")
            elif phase < 30:
                score += 8

            # WRITE DENSITY (many writes to small region)
            density = len(group) / span if span > 0 else 0
            if density > 0.8:
                score += 10
                evidence.append(f"✓ High density: {density:.2f} writes/byte")

            scored.append({
                'group': group,
                'score': score,
                'evidence': evidence,
                'span': span,
                'total_bytes': total_bytes,
                'addrs': addrs,
                'instrs': instrs
            })

        # Sort by score
        scored.sort(key=lambda x: x['score'], reverse=True)

        # Display
        for i, item in enumerate(scored[:10], 1):
            score = item['score']
            span = item['span']
            total_bytes = item['total_bytes']

            if score >= 150:
                confidence = "🔥🔥🔥 VERY HIGH"
            elif score >= 100:
                confidence = "🔥🔥 HIGH"
            elif score >= 50:
                confidence = "🔥 MEDIUM"
            else:
                confidence = "⚠️  LOW"

            print(f"  [{i}] Score: {score}/235 {confidence}")
            print(f"      Address: 0x{min(item['addrs']):016x} - 0x{max(item['addrs']):016x}")
            print(f"      Span: {span} bytes | Total written: {total_bytes} bytes")
            print(f"      Writes: {len(item['group'])}")
            print(f"      Instructions: {min(item['instrs']):,} - {max(item['instrs']):,}")

            if item['evidence']:
                print(f"      Evidence:")
                for ev in item['evidence']:
                    print(f"        • {ev}")

            print()

        return scored

    def generate_report(self, candidates):
        """Generate report"""

        print("="*80)
        print("VULNERABILITY REPORT")
        print("="*80)
        print()

        if not candidates:
            print("No overflow candidates found")
            return

        best = candidates[0]
        score = best['score']

        print(f"Vulnerability Type: Stack Buffer Overflow")
        print(f"Confidence: {min(100, int(score * 100 / 235))}%")
        print()

        if score >= 150:
            print("✅ VERY HIGH CONFIDENCE")
            print("   Multiple strong indicators of overflow")
        elif score >= 100:
            print("✅ HIGH CONFIDENCE")
            print("   Strong size correlation")
        elif score >= 50:
            print("⚠️  MEDIUM CONFIDENCE")
            print("   Some indicators present")
        else:
            print("? LOW CONFIDENCE")
            print("   Weak indicators")

        print()
        print("Primary Candidate:")
        print(f"  Address: 0x{min(best['addrs']):016x} - 0x{max(best['addrs']):016x}")
        print(f"  Span: {best['span']} bytes")
        print(f"  Total written: {best['total_bytes']} bytes")
        print(f"  Writes: {len(best['group'])}")
        print(f"  Instructions: {min(best['instrs']):,} - {max(best['instrs']):,}")
        print()

        if best['evidence']:
            print("Evidence:")
            for ev in best['evidence']:
                print(f"  • {ev}")
            print()

        print("Input Characteristics:")
        print(f"  Size: {len(self.input_bytes)} bytes")
        print(f"  Pattern: {self.input_bytes[:40].decode('latin-1', errors='replace')}")
        print()

        if score >= 100:
            print("Recommended Actions:")
            print(f"  1. Verify with GDB")
            print(f"  2. Check instructions {min(best['instrs']):,}-{max(best['instrs']):,}")
            print(f"  3. Look for strcpy/memcpy")
            print(f"  4. Calculate exact buffer size")

        print()
        print("Note: Analysis based on size correlation without byte values")
        print("      Use GDB verification for definitive proof")
        print()

    def analyze(self):
        """Run analysis"""

        if not self.load_input():
            return

        trace = self.generate_trace()
        if not trace:
            return

        self.parse_writes(trace)
        candidates = self.find_overflow_candidates()
        self.generate_report(candidates)

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Size-based overflow analyzer (no byte values needed)',
        epilog='Uses size correlation and pattern analysis instead of taint tracking')

    parser.add_argument('trace_dir', help='DynamoRIO trace directory')
    parser.add_argument('--arg', type=int, default=2, help='Argument index (default: 2)')

    args = parser.parse_args()

    if not os.path.isdir(args.trace_dir):
        print(f"Error: Directory not found: {args.trace_dir}")
        sys.exit(1)

    analyzer = SizeBasedAnalyzer(args.trace_dir, args.arg)
    analyzer.analyze()

    binary = analyzer.all_args[0].decode("latin-1")
    bin_args = [b.decode("latin-1") for b in analyzer.all_args[1:]]
    verifier = CompleteAnalyzer(binary,bin_args,int(args.arg-1))
    verifier.run()

if __name__ == '__main__':
    main()
