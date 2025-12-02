#!/usr/bin/env python3
"""
Simplified ARGV to Buffer Overflow Analyzer - Proof of Concept
Tracks only command-line arguments (argv) flowing to buffer overflow sinks
"""

import angr
import sys
import os
import subprocess
import re
import json
import datetime
import argparse
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Set, Optional, Dict
import logging

# Import AI Analyzer
from ai_analyzer import AIAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Suppress angr warnings
logging.getLogger('angr').setLevel(logging.ERROR)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
os.mkdir(f"SVDS_Static-{timestamp}")
dirname = f"SVDS_Static-{timestamp}"

@dataclass
class VulnerablePath:
    """Represents a path from argv to buffer overflow sink"""
    argv_index: str  # argv[1], argv[2], etc. or just 'argv'
    sink_function: str
    sink_type: str
    complete_path: List[str]
    
    def __str__(self):
        return " -> ".join(self.complete_path)

class ArgvBufferOverflowAnalyzer:
    """Simplified analyzer for argv to buffer overflow vulnerabilities"""
    
    def __init__(self, binary_path: str, ai_provider: str = None):
        self.binary_path = binary_path
        self.ai_provider = ai_provider
        self.ai_analyzer = None
        if self.ai_provider:
            self.ai_analyzer = AIAnalyzer(provider=self.ai_provider)
            logger.info(f"AI Analysis enabled using {self.ai_provider}")
            
        self.proj = None
        self.cfg = None
        
        # Call graph
        self.call_graph = defaultdict(set)
        
        # Buffer overflow sinks only
        self.buffer_overflow_sinks = {
            'strcpy': ['strcpy', 'wcscpy'],
            'strcat': ['strcat', 'wcscat'],
            'gets': ['gets'],
            'sprintf': ['sprintf', 'vsprintf'],
            'memcpy': ['memcpy', 'memmove', 'bcopy']
        }
        
        # Results
        self.vulnerabilities = []
    
    def analyze(self):
        """Run simplified analysis"""
        logger.info(f"\nAnalyzing {self.binary_path} for argv → buffer overflow paths\n")
        
        # Step 1: Build call graph
        logger.info("Step 1: Building call graph...")
        self._build_call_graph()
        
        # Step 2: Find argv usage
        logger.info("Step 2: Identifying argv usage in main...")
        argv_info = self._find_argv_usage()
        
        # Step 3: Find paths from main to buffer overflow sinks
        logger.info("Step 3: Finding paths from main to buffer overflow sinks...")
        self._find_vulnerable_paths(argv_info)
        
        return self.vulnerabilities
    
    def _build_call_graph(self):
        """Build simplified call graph"""
        try:
            # Use angr
            self.proj = angr.Project(self.binary_path, auto_load_libs=False)
            self.cfg = self.proj.analyses.CFGFast(normalize=True)
            
            # Build call graph
            for func_addr, func in self.cfg.functions.items():
                caller = func.name or f"sub_{func_addr:x}"
                
                # Get all functions called by this one
                for called_addr in self.cfg.kb.functions.callgraph.successors(func_addr):
                    if called_addr in self.cfg.functions:
                        callee = self.cfg.functions[called_addr].name
                        self.call_graph[caller].add(callee)
            
            logger.info(f"  Found {len(self.call_graph)} functions")
            
        except Exception as e:
            logger.warning(f"  angr failed, trying objdump: {e}")
            self._build_with_objdump()
    
    def _build_with_objdump(self):
        """Fallback: Build call graph with objdump"""
        try:
            result = subprocess.run(
                ['objdump', '-d', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            
            current_func = None
            for line in result.stdout.split('\n'):
                # Function start
                if '<' in line and '>:' in line:
                    match = re.search(r'<(.+?)>', line)
                    if match:
                        current_func = match.group(1).split('@')[0]
                
                # Function call
                elif current_func and 'call' in line:
                    if '<' in line:
                        match = re.search(r'<(.+?)>', line)
                        if match:
                            target = match.group(1).split('@')[0]
                            self.call_graph[current_func].add(target)
        except:
            pass
    
    def _find_argv_usage(self) -> List[str]:
        """Determine which specific argv indices are used"""
        argv_indices = []
        
        # Method 1: Analyze with angr if available
        if self.cfg:
            argv_indices.extend(self._find_argv_with_angr())
        
        # Method 2: Analyze with objdump
        argv_indices.extend(self._find_argv_with_objdump())
        
        # Deduplicate and sort
        argv_indices = sorted(list(set(argv_indices)))
        
        if argv_indices:
            logger.info(f"  Detected argv usage: {argv_indices}")
            return argv_indices
        else:
            logger.info("  Assuming general argv usage")
            return ['argv']  # Generic if we can't determine specific indices
    
    def _find_argv_with_angr(self) -> List[str]:
        """Use angr to find argv usage patterns"""
        indices = []
        
        # Find main function
        main_func = None
        for addr, func in self.cfg.functions.items():
            if func.name == 'main':
                main_func = func
                break
        
        if not main_func:
            return indices
        
        # Analyze main's blocks for argv access patterns
        for block in main_func.blocks:
            try:
                if hasattr(block, 'capstone'):
                    for insn in block.capstone.insns:
                        # x86-64: argv is typically in rsi register
                        # Look for patterns like: mov rax, [rsi+0x8] (argv[1])
                        if 'rsi' in str(insn):
                            if '+0x8]' in str(insn) or '+ 8]' in str(insn) or '+ 0x8]' in str(insn):
                                indices.append('argv[1]')
                            elif '+0x10]' in str(insn) or '+ 0x10]' in str(insn) or '+ 16]' in str(insn):
                                indices.append('argv[2]')
                            elif '+0x18]' in str(insn) or '+ 0x18]' in str(insn) or '+ 24]' in str(insn):
                                indices.append('argv[3]')
                            elif '+0x20]' in str(insn) or '+ 0x20]' in str(insn) or '+ 32]' in str(insn):
                                indices.append('argv[4]')
            except:
                pass
        
        return indices
    
    def _find_argv_with_objdump(self) -> List[str]:
        """Use objdump to find argv usage patterns"""
        indices = []
        
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            
            in_main = False
            # Track which registers hold argv
            argv_register = None
            
            for line in result.stdout.split('\n'):
                # Check if we're in main function
                if '<main>' in line or '<main@@' in line:
                    in_main = True
                elif in_main and '>' in line and '<' in line and 'main' not in line:
                    in_main = False
                
                if in_main:
                    # In x86-64 ABI, main receives: rdi=argc, rsi=argv
                    if 'mov' in line and 'rsi' in line:
                        # Track which register gets argv
                        if 'rbp' in line or 'rsp' in line:
                            # Saving argv to stack
                            if 'qword ptr [rbp' in line:
                                argv_register = 'stack'
                        elif 'rax' in line or 'rdx' in line or 'rcx' in line:
                            # Moving argv to another register
                            parts = line.split(',')
                            if len(parts) == 2:
                                dest = parts[0].split()[-1]
                                if 'rsi' in parts[1]:
                                    argv_register = dest
                    
                    # Look for argv array access patterns
                    # Pattern 1: Direct offset from rsi (argv)
                    if 'qword ptr [rsi' in line or (argv_register and f'qword ptr [{argv_register}' in line):
                        if '+ 0x8]' in line or '+0x8]' in line or '+ 8]' in line:
                            indices.append('argv[1]')
                        elif '+ 0x10]' in line or '+0x10]' in line or '+ 16]' in line:
                            indices.append('argv[2]')
                        elif '+ 0x18]' in line or '+0x18]' in line or '+ 24]' in line:
                            indices.append('argv[3]')
                        elif '+ 0x20]' in line or '+0x20]' in line or '+ 32]' in line:
                            indices.append('argv[4]')
                    
                    # Pattern 2: Loop through argv (often indicates processing all args)
                    if 'cmp' in line and 'edi' in line:  # Comparing with argc
                        if 'loop' in line or 'jmp' in line or 'jne' in line:
                            indices.append('argv[1..n]')  # Multiple args processed
                    
                    # Pattern 3: Check for specific argc values
                    if 'cmp' in line and 'edi' in line:
                        # Check if comparing argc with specific values
                        if ', 0x2' in line or ', 2' in line:
                            indices.append('argv[1]')  # Expects 1 argument
                        elif ', 0x3' in line or ', 3' in line:
                            indices.extend(['argv[1]', 'argv[2]'])  # Expects 2 arguments
                        elif ', 0x4' in line or ', 4' in line:
                            indices.extend(['argv[1]', 'argv[2]', 'argv[3]'])  # Expects 3 arguments
            
        except Exception as e:
            logger.warning(f"  objdump analysis failed: {e}")
        
        return indices
    
    def _find_vulnerable_paths(self, argv_info: List[str]):
        """Find paths using hybrid parameter tracking + call graph analysis"""
        
        if not argv_info or 'main' not in self.call_graph:
            logger.warning("  No main function found or no argv usage detected")
            return
        
        logger.info("  Using hybrid parameter tracking for argv flow analysis...")
        
        # Step 1: Analyze main function to determine which argv goes where
        argv_to_functions = self._analyze_argv_parameter_passing()
        
        # Step 2: For each tracked flow, find paths to sinks
        if argv_to_functions:
            for argv_idx, target_funcs in argv_to_functions.items():
                for target_func in target_funcs:
                    self._trace_function_to_sinks(argv_idx, target_func)
        else:
            # Fallback if parameter tracking fails
            logger.info("  Parameter tracking incomplete, using fallback...")
            self._fallback_analysis(argv_info)
    
    def _analyze_argv_parameter_passing(self) -> Dict[str, Set[str]]:
        """Analyze main() to determine which argv[i] is passed to which functions"""
        import re
        
        argv_flows = defaultdict(set)
        
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            
            in_main = False
            lines = result.stdout.split('\n')
            
            # Track register contents
            register_map = {}  # reg -> content descriptor
            argv_stack_location = None  # Where argv is stored on stack
            
            for i, line in enumerate(lines):
                # Check if we're in main
                if '<main>' in line or '<main@@' in line:
                    in_main = True
                    register_map = {}
                    argv_stack_location = None
                elif in_main and line.strip() and ':' not in line and '<' in line and '>:' in line:
                    # New function definition (has address, colon, angle brackets)
                    in_main = False
                
                if not in_main:
                    continue
                
                # Step 0: Detect where argv (rsi) is stored on stack
                # Pattern: mov QWORD PTR [rbp-0xa0],rsi (or any offset)
                if 'mov' in line and 'rsi' in line and ('[rbp' in line or '[rsp' in line):
                    stack_match = re.search(r'\[(rbp|rsp)([-+])(0x)?([0-9a-f]+)\]', line, re.I)
                    if stack_match:
                        base_reg = stack_match.group(1)
                        sign = stack_match.group(2)
                        offset = stack_match.group(4)
                        argv_stack_location = f'[{base_reg}{sign}0x{offset}]'
                        logger.info(f"    argv saved at {argv_stack_location}")
                
                # Step 1: Load argv pointer from stack (using detected location)
                # Pattern: mov rax, QWORD PTR [rbp-0xa0] (or whatever location we detected)
                if 'mov' in line and argv_stack_location and argv_stack_location in line:
                    parts = line.split(',')
                    if len(parts) == 2 and 'rsi' not in line:
                        dest_reg = parts[0].split()[-1].strip()
                        register_map[dest_reg] = 'argv_base'
                        logger.info(f"    {dest_reg} = argv_base")
                
                # Step 2: Add offset to get argv[i] pointer address
                # Pattern: add rax, 0x8 (or 0x10, 0x18)
                if 'add' in line:
                    parts = line.split(',')
                    if len(parts) == 2:
                        reg = parts[0].split()[-1].strip()
                        offset_part = parts[1].strip()
                        
                        if reg in register_map and register_map[reg] == 'argv_base':
                            # Extract offset value
                            if '0x8' in offset_part or ',0x8' in offset_part:
                                register_map[reg] = 'argv[1]_ptr'
                            elif '0x10' in offset_part or ',0x10' in offset_part:
                                register_map[reg] = 'argv[2]_ptr'
                            elif '0x18' in offset_part or ',0x18' in offset_part:
                                register_map[reg] = 'argv[3]_ptr'
                            elif '0x20' in offset_part or ',0x20' in offset_part:
                                register_map[reg] = 'argv[4]_ptr'
                
                # Step 3: Dereference patterns (handles TWO styles)
                # Pattern: mov rax, QWORD PTR [rax] OR mov rax, QWORD PTR [rax+0x8]
                if 'mov' in line and 'qword ptr [' in line.lower():
                    parts = line.split(',')
                    if len(parts) == 2:
                        dest_reg = parts[0].split()[-1].strip()
                        src_part = parts[1]
                        
                        # PATTERN A: [reg+offset] - Direct access (e.g., mov rax, [rax+0x8])
                        # This is used by two_args_vuln and many optimized binaries
                        offset_match = re.search(r'\[([a-z0-9]+)\s*\+\s*(0x)?([0-9a-f]+)\]', src_part, re.I)
                        if offset_match:
                            src_reg = offset_match.group(1)
                            offset_hex = offset_match.group(3)
                            offset_val = int(offset_hex, 16)
                            
                            # Check if source register contains argv
                            if src_reg in register_map and 'argv' in register_map[src_reg]:
                                argv_idx = offset_val // 8
                                if 0 <= argv_idx <= 10:
                                    register_map[dest_reg] = f'argv[{argv_idx}]'
                                    logger.info(f"    {dest_reg} = argv[{argv_idx}] (direct via [{src_reg}+{hex(offset_val)}])")
                        
                        # PATTERN B: [reg] - Simple dereference (e.g., mov rax, [rax])
                        # This is used after a separate 'add' instruction
                        else:
                            simple_match = re.search(r'\[([a-z0-9]+)\]', src_part, re.I)
                            if simple_match:
                                src_reg = simple_match.group(1)
                                
                                if src_reg in register_map:
                                    # Dereferencing argv[i]_ptr gives us argv[i] string
                                    if '_ptr' in register_map[src_reg]:
                                        register_map[dest_reg] = register_map[src_reg].replace('_ptr', '')
                                        logger.info(f"    {dest_reg} = *{src_reg} = {register_map[dest_reg]}")
                                    # Dereferencing argv_base with no offset gives argv[0]
                                    elif register_map[src_reg] == 'argv_base':
                                        register_map[dest_reg] = 'argv[0]'
                                        logger.info(f"    {dest_reg} = argv[0]")
                
                # Step 4: Copy to parameter register
                # Pattern: mov rdi, rax
                if 'mov' in line and 'ptr' not in line:
                    parts = line.split(',')
                    if len(parts) == 2:
                        dest = parts[0].split()[-1].strip()
                        src = parts[1].strip()
                        if src in register_map:
                            register_map[dest] = register_map[src]
                            if 'argv[' in register_map[src]:
                                logger.info(f"    {dest} = {register_map[src]}")
                
                # Step 5: Function call - track ALL parameter registers
                # Pattern: call <function>
                if 'call' in line:
                    match = re.search(r'<(.+?)>', line)
                    if match:
                        func_name = match.group(1).split('@')[0]
                        
                        # Skip PLT entries and main itself
                        if func_name and func_name != 'main' and 'plt' not in func_name:
                            # Check ALL parameter registers (x86-64 calling convention)
                            # rdi=1st, rsi=2nd, rdx=3rd, rcx=4th, r8=5th, r9=6th
                            param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                            
                            found_argv = False
                            for param_idx, param_reg in enumerate(param_regs):
                                if param_reg in register_map and 'argv[' in register_map[param_reg]:
                                    argv_val = register_map[param_reg]
                                    
                                    # Skip argv[0] (program name) unless explicitly requested
                                    if argv_val == 'argv[0]':
                                        continue
                                    
                                    argv_flows[argv_val].add(func_name)
                                    logger.info(f"    ✓ Flow: {argv_val} → {func_name} (via {param_reg})")
                                    
                                    # Check if this is a wrapper function (not a known sink)
                                    is_sink = False
                                    for sink_type, patterns in self.buffer_overflow_sinks.items():
                                        if any(pattern in func_name.lower() for pattern in patterns):
                                            is_sink = True
                                            break
                                    
                                    # Only analyze non-sink functions for argv propagation
                                    if not is_sink and not found_argv:
                                        # Pass which parameter position the argv is in
                                        self._analyze_intermediate_function(func_name, argv_val, param_idx, argv_flows)
                                        found_argv = True  # Only analyze once per call
        
        except Exception as e:
            logger.warning(f"  Parameter analysis failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
        
        return dict(argv_flows)
    
    def _analyze_intermediate_function(self, func_name: str, argv_val: str, param_position: int, argv_flows: Dict[str, Set[str]]):
        """Analyze an intermediate function to see if it passes argv to other functions
        
        Args:
            func_name: Name of function to analyze
            argv_val: Which argv (e.g., "argv[1]")
            param_position: Which parameter position (0=rdi, 1=rsi, 2=rdx, etc.)
            argv_flows: Dictionary to update with discovered flows
        """
        import re
        
        # Skip if this is already a known sink (don't double-count)
        for sink_type, patterns in self.buffer_overflow_sinks.items():
            for pattern in patterns:
                if pattern in func_name.lower():
                    return
        
        # Only analyze user-defined functions (not library functions)
        if any(x in func_name for x in ['@plt', '.plt', 'libc', 'glibc']):
            return
        
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            
            in_target_func = False
            lines = result.stdout.split('\n')
            register_map = {}
            
            # Map parameter position to register name
            param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            initial_reg = param_regs[param_position] if param_position < len(param_regs) else 'rdi'
            
            # Look for the target function
            for i, line in enumerate(lines):
                if f'<{func_name}>' in line and ':' in line:
                    in_target_func = True
                    register_map = {}
                    # Track that the parameter register initially contains argv
                    register_map[initial_reg] = argv_val
                    logger.info(f"      Analyzing {func_name} (argv in {initial_reg})...")
                elif in_target_func and line.strip() and '<' in line and '>:' in line and func_name not in line:
                    break
                
                if not in_target_func:
                    continue
                
                # Track register moves within this function
                if 'mov' in line and 'ptr' not in line:
                    parts = line.split(',')
                    if len(parts) == 2:
                        dest = parts[0].split()[-1].strip()
                        src = parts[1].strip()
                        if src in register_map and 'argv[' in register_map[src]:
                            register_map[dest] = register_map[src]
                
                # Check for calls to other functions (but don't recurse infinitely)
                if 'call' in line:
                    match = re.search(r'<(.+?)>', line)
                    if match:
                        called_func = match.group(1).split('@')[0]
                        if 'plt' not in called_func and called_func != func_name:
                            # Check ALL parameter registers for argv propagation
                            for param_reg in param_regs:
                                if param_reg in register_map and 'argv[' in register_map[param_reg]:
                                    # Only add to flows, don't recurse to prevent infinite loops
                                    argv_flows[argv_val].add(called_func)
                                    logger.info(f"      → {func_name} passes {argv_val} to {called_func} (via {param_reg})")
                                    break
        
        except Exception as e:
            logger.debug(f"  Failed to analyze {func_name}: {e}")
    
    
    def _trace_function_to_sinks(self, argv_idx: str, start_func: str):
        """Trace from a specific function to buffer overflow sinks"""
        
        # BFS from start_func to find sinks
        visited = set()
        queue = [(start_func, [start_func])]
        
        while queue:
            current_func, path = queue.pop(0)
            
            if current_func in visited:
                continue
            visited.add(current_func)
            
            # Check if this function itself is a sink
            for sink_type, patterns in self.buffer_overflow_sinks.items():
                for pattern in patterns:
                    if pattern in current_func.lower():
                        vuln = VulnerablePath(
                            argv_index=argv_idx,
                            sink_function=current_func,
                            sink_type=sink_type,
                            complete_path=['main'] + path
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"    ✓ Flow confirmed: {argv_idx} → {current_func}")
            
            # Explore callees
            for callee in self.call_graph.get(current_func, []):
                new_path = path + [callee]
                
                # Check if callee is a sink
                for sink_type, patterns in self.buffer_overflow_sinks.items():
                    for pattern in patterns:
                        if pattern in callee.lower():
                            vuln = VulnerablePath(
                                argv_index=argv_idx,
                                sink_function=callee,
                                sink_type=sink_type,
                                complete_path=['main'] + new_path
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"    ✓ Flow confirmed: {argv_idx} → {callee}")
                
                # Continue exploring (with depth limit)
                if callee not in visited and len(new_path) < 10:
                    queue.append((callee, new_path))
    
    def _check_if_sink(self, func_name: str, state) -> Optional[tuple]:
        """Check if current function is a buffer overflow sink"""
        if not func_name:
            return None
        
        func_lower = func_name.lower()
        for sink_type, patterns in self.buffer_overflow_sinks.items():
            for pattern in patterns:
                if pattern in func_lower:
                    return (sink_type, func_name)
        return None
    
    def _check_taint_at_sink(self, state) -> bool:
        """Check if tainted data reaches the sink function's parameters"""
        import claripy
        
        if 'tainted_name' not in state.globals:
            return False
        
        tainted_name = state.globals['tainted_name']
        
        # Check function parameters (registers for x86-64 calling convention)
        # rdi = 1st arg, rsi = 2nd arg, rdx = 3rd arg, etc.
        param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        
        for reg_name in param_regs:
            try:
                reg_val = getattr(state.regs, reg_name)
                
                # Check if register is symbolic
                if reg_val.symbolic:
                    # Check if it contains our tainted variable
                    if tainted_name in str(reg_val.variables):
                        return True
                
                # Also check if register points to memory containing taint
                if reg_val.concrete:
                    try:
                        addr = state.solver.eval(reg_val)
                        # Read some bytes from this address
                        mem_data = state.memory.load(addr, 64, endness='Iend_LE')
                        if mem_data.symbolic and tainted_name in str(mem_data.variables):
                            return True
                    except:
                        pass
            except:
                pass
        
        return False

    
    def _fallback_analysis(self, argv_info: List[str]):
        """Fallback to call graph analysis when symbolic execution fails"""
        logger.info("  Using call graph analysis (limited precision)...")
        
        # BFS from main to find all reachable sinks
        visited = set()
        queue = [('main', ['main'])]
        
        found_sinks = []
        
        while queue:
            current_func, path = queue.pop(0)
            
            if current_func in visited:
                continue
            visited.add(current_func)
            
            # Check if any callee is a buffer overflow sink
            for callee in self.call_graph.get(current_func, []):
                new_path = path + [callee]
                
                # Check if this is a vulnerable sink
                for sink_type, patterns in self.buffer_overflow_sinks.items():
                    for pattern in patterns:
                        if pattern in callee.lower():
                            found_sinks.append((sink_type, callee, new_path))
                
                # Continue exploring
                if callee not in visited:
                    queue.append((callee, new_path))
        
        # Report with uncertainty
        if found_sinks:
            # Since we can't determine exact argv mapping, report all possible
            argv_str = "argv[" + ",".join([a.split('[')[1].split(']')[0] for a in argv_info if '[' in a]) + "]"
            
            for sink_type, sink_func, path in found_sinks:
                vuln = VulnerablePath(
                    argv_index=f"{argv_str} (unconfirmed)",
                    sink_function=sink_func,
                    sink_type=sink_type,
                    complete_path=path
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"    Found possible: {argv_str} → {' → '.join(path[-3:])}")
    
    def generate_report(self) -> str:
        """Generate simplified report"""
        report = []
        report.append("\n" + "=" * 70)
        report.append("ARGV → BUFFER OVERFLOW VULNERABILITY REPORT")
        report.append("=" * 70)
        report.append(f"Binary: {self.binary_path}\n")
        
        if not self.vulnerabilities:
            report.append("No argv to buffer overflow paths found.")
            return "\n".join(report)
        
        # Group by sink type
        by_type = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_type[vuln.sink_type].append(vuln)
        
        for sink_type, vulns in by_type.items():
            report.append(f"\n{sink_type.upper()} Buffer Overflows ({len(vulns)} paths):")
            report.append("-" * 40)
            
            # Group by argv index within each sink type
            by_argv = defaultdict(list)
            for vuln in vulns:
                by_argv[vuln.argv_index].append(vuln)
            
            for argv_idx, idx_vulns in by_argv.items():
                report.append(f"\n  From {argv_idx}:")
                
                for i, vuln in enumerate(idx_vulns[:3], 1):  # Show top 3 per argv index
                    report.append(f"    [{i}] Path to {vuln.sink_function}:")
                    report.append(f"        {' → '.join(vuln.complete_path)}")
                    report.append(f"        Length: {len(vuln.complete_path)} functions")
                    
                    # Risk assessment based on specific argv
                    if 'argv[1]' in argv_idx:
                        risk_note = " (first argument - commonly user-controlled)"
                    elif 'argv[2]' in argv_idx:
                        risk_note = " (second argument)"
                    elif 'argv[1..n]' in argv_idx:
                        risk_note = " (multiple arguments processed)"
                    else:
                        risk_note = ""
                    
                    # Risk level
                    if sink_type == 'gets':
                        risk = f"CRITICAL - No bounds checking{risk_note}"
                    elif sink_type == 'strcpy':
                        risk = f"HIGH - No size validation{risk_note}"
                    elif sink_type == 'sprintf':
                        risk = f"HIGH - Format string buffer overflow{risk_note}"
                    elif sink_type == 'memcpy':
                        risk = f"MEDIUM - Size may be controlled{risk_note}"
                    else:
                        risk = f"MEDIUM{risk_note}"
                    
                    report.append(f"        Risk: {risk}")
        
        # Summary
        report.append("\n" + "=" * 70)
        report.append(f"Total vulnerabilities: {len(self.vulnerabilities)}")
        
        return "\n".join(report)

    def analyze_with_ai(self) -> Dict[str, str]:
        """Run AI analysis on vulnerabilities"""
        if not self.ai_analyzer or not self.vulnerabilities:
            return {}
            
        ai_results = {}
        logger.info("Initializing AI Assistant with full binary context...")
        
        # 1. Aggregate Context (Full Assembly)
        # We need to get assembly for all functions in the call graph
        full_context = []
        
        # Collect all functions involved in vulnerabilities
        relevant_funcs = set()
        for vuln in self.vulnerabilities:
            relevant_funcs.update(vuln.complete_path)
            
        # Add main if not present
        relevant_funcs.add('main')
        
        # Try to get assembly from angr CFG
        if self.cfg:
            for func_name in sorted(list(relevant_funcs)):
                full_context.append(f"Function: {func_name}")
                
                # Find function in CFG
                found = False
                for addr, func in self.cfg.functions.items():
                    if func.name == func_name:
                        found = True
                        for block in func.blocks:
                            try:
                                if hasattr(block, 'capstone'):
                                    for insn in block.capstone.insns:
                                        full_context.append(f"  {insn.mnemonic} {insn.op_str}")
                            except:
                                pass
                        break
                
                if not found:
                    full_context.append("  (Assembly not available via angr)")
                full_context.append("")
        else:
            # Fallback to objdump if no CFG
            try:
                result = subprocess.run(
                    ['objdump', '-d', self.binary_path],
                    capture_output=True, text=True, timeout=10
                )
                full_context.append(result.stdout)
            except:
                full_context.append("(Assembly not available)")
        
        context_text = "\n".join(full_context)
        
        # Step 1: Recover C code 
        logger.info(f"Sending context to AI for C recovery...")
        recovered_c = self.ai_analyzer.recover_c_code(context_text)
        
        # Write AI Recovered C code to file
        with open(f"{dirname}/recovered_code.c", "w") as f:
            f.write(recovered_c)

        # Prepare paths for analysis
        paths_data = []
        path_map = {} # Map ID back to vuln object
        
        for i, vuln in enumerate(self.vulnerabilities):
            path_str = " -> ".join(vuln.complete_path)
            paths_data.append({
                "id": i,
                "path": path_str,
                "sink": vuln.sink_function
            })
            path_map[i] = vuln
            
        # Step 2: Analyze paths using recovered C code
        logger.info(f"Sending {len(paths_data)} paths to AI ...")
        json_response = self.ai_analyzer.analyze_paths_bulk(paths_data, recovered_c)
       
        # Write AI response to JSON
        with open(f"{dirname}/ai_response.json", "w") as f:
            json.dump(json_response, f, indent=4)

        # Parse Results
        try:
            if "```json" in json_response:
                json_response = json_response.split("```json")[1].split("```")[0].strip()
            elif "```" in json_response:
                json_response = json_response.split("```")[1].split("```")[0].strip()
            
            results_list = json.loads(json_response)
            
            confirmed_paths = []
            
            for result in results_list:
                path_id = result.get("id")
                if path_id is not None and path_id in path_map:
                    vuln = path_map[path_id]
                    verdict = result.get("verdict", "Unknown")
                    reasoning = result.get("reasoning", "No reasoning provided")
                    
                    # Create a unique key for the result
                    path_key = f"{vuln.argv_index} -> {vuln.sink_function}"
                    ai_results[path_key] = f"Verdict: {verdict}\nReasoning: {reasoning}"
                    
                    # Check for True Positive
                    if "True Positive" in verdict:
                        confirmed_paths.append({
                            "id": path_id,
                            "path": " -> ".join(vuln.complete_path),
                            "sink": vuln.sink_function,
                            "verdict": verdict,
                            "reasoning": reasoning
                        })
            
            # Save confirmed paths to file
            if confirmed_paths:
                with open(f"{dirname}/ai_confirmed_paths.txt", "w") as f:
                    f.write("AI CONFIRMED VULNERABILITY PATHS\n")
                    f.write("=" * 80 + "\n\n")
                    for p in confirmed_paths:
                        f.write(f"Path ID: {p['id']}\n")
                        f.write(f"Sink: {p['sink']}\n")
                        f.write(f"Path: {p['path']}\n")
                        f.write(f"Verdict: {p['verdict']}\n")
                        f.write(f"Reasoning: {p['reasoning']}\n")
                        f.write("-" * 60 + "\n\n")
                logger.info(f"Saved {len(confirmed_paths)} confirmed paths to ai_confirmed_paths.txt")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI JSON response: {e}")
 
        logger.info("AI analysis complete.")
        return ai_results

def main():
    parser = argparse.ArgumentParser(description="Simplified ARGV to Buffer Overflow Analyzer")
    parser.add_argument("binary", help="Path to the binary file")
    parser.add_argument("--ai", nargs='?', const="openai", choices=["openai", "google"], help="Enable AI analysis with specified provider (default: openai)")
    args = parser.parse_args()
    
    binary = args.binary
    if not os.path.exists(binary):
        print(f"Error: {binary} not found")
        sys.exit(1)
    
    # Run analysis
    analyzer = ArgvBufferOverflowAnalyzer(binary, ai_provider=args.ai)
    vulnerabilities = analyzer.analyze()
    
    # Generate and print report
    report = analyzer.generate_report()
    print(report)
    
    report_filename = f"{dirname}/report_{timestamp}.txt"
        
    # Run AI analysis
    if args.ai:
        ai_results = analyzer.analyze_with_ai()
        # Write AI results to a separate file
        if ai_results:
            ai_report_content = []
            ai_report_content.append("=" * 80)
            print("=" * 80)
            ai_report_content.append("AI VULNERABILITY ANALYSIS")
            print("AI VULNERABILITY ANALYSIS")
            ai_report_content.append("=" * 80)
            print("=" * 80)
            ai_report_content.append(f"Binary: {binary}\n")
            print(f"Binary: {binary}\n")
            
            for path_key, result in ai_results.items():
                ai_report_content.append(f"Path: {path_key}")
                ai_report_content.append("-" * 40)
                ai_report_content.append(result)
                ai_report_content.append("-" * 80 + "\n")
           
                if "false positive" not in result.lower():
                    print(f"Path: {path_key}")
                    print("-" * 40)
                    print(result)
                    print("-" * 80 + "\n")

                report = report + "\n".join(ai_report_content)

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Results written to {report_filename}")

if __name__ == "__main__":
    main()
