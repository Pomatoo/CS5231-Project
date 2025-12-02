#!/bin/bash
python afl_fuzzer.py -b ./five_args_vuln_wrapper_arg4 -i seeds -o five_args_vuln_wrapper_arg4_findings -t 60 -r five_args_vuln_wrapper_arg4_crash_report.json
