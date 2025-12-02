import argparse
import os
import subprocess
import sys

# Default static values for arguments when they are not being fuzzed
DEFAULT_STATIC_VALUE = "A"
to_run = []

def generate_wrapper_code(vuln_binary_path, total_args, fuzz_index):
    """Generates the C source code for a wrapper fuzzing the argument at fuzz_index."""
    
    # Construct the absolute path logic
    # We'll generate C code that resolves the absolute path at runtime
    
    c_code_path_resolution = ""
    vuln_path_var = f'"{vuln_binary_path}"' 

    clean_path = vuln_binary_path
    if clean_path.startswith("./"):
        clean_path = clean_path[2:]
    elif clean_path.startswith(".\\"): 
        clean_path = clean_path[2:]
        
    # Escape for C string
    clean_path_safe = clean_path.replace("\\", "\\\\")
    
    c_code_path_resolution = f"""
    // Resolve absolute path to vuln binary
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {{
        perror("getcwd");
        return 1;
    }}
    
    char vuln_path[PATH_MAX];
    snprintf(vuln_path, sizeof(vuln_path), "%s/{clean_path_safe}", cwd);
    """
    
    vuln_path_var = "vuln_path"

    # Construct the args array initialization
    args_init = []
    args_init.append(f'        {vuln_path_var},   // argv[0]') 
    
    for i in range(1, total_args + 1):
        if i == fuzz_index:
            args_init.append(f'        fuzz_string,  // argv[{i}] (FUZZED)')
        else:
            val = f"{DEFAULT_STATIC_VALUE}_{i}"
            args_init.append(f'        "{val}",   // argv[{i}] (STATIC)')
    
    args_init.append('        NULL')
    args_init_str = '\n'.join(args_init)

    c_code = f"""#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>

int main(int argc, char* argv[]) {{
    
    // AFL calls this wrapper like: ./wrapper <path_to_input_file>
    if (argc < 2) return 1;

    // ---------------------------------------------------------
    // STEP 1: READ THE FILE (The "Translation" Step)
    // ---------------------------------------------------------
    // Open the file AFL created
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;

    // Get file size
    struct stat st;
    fstat(fd, &st);

    // Create a buffer to hold the text
    char *fuzz_string = malloc(st.st_size + 1);
    if (!fuzz_string) {{
        close(fd);
        return 1;
    }}
    
    // Read the file content INTO the buffer
    read(fd, fuzz_string, st.st_size);
    
    // IMPORTANT: Turn it into a valid C-String by adding NULL at the end
    fuzz_string[st.st_size] = '\\0';
    
    close(fd);
    // ---------------------------------------------------------

    {c_code_path_resolution}

    // ---------------------------------------------------------
    // STEP 2: RUN THE BINARY (Pass the content as Arg2)
    // ---------------------------------------------------------
    char *new_argv[] = {{
{args_init_str}
    }};

    // Replace current process with the target
    execv(new_argv[0], new_argv);
    perror("execv");

    return 0;
}}
"""
    return c_code

def main():
    parser = argparse.ArgumentParser(description="Generate AFL wrappers")
    parser.add_argument("vuln_path", help="Path to the vulnerable binary")
    parser.add_argument("total_args", type=int, help="Total number of arguments")
    parser.add_argument("fuzz_indices", help="Comma-separated list of indices to fuzz (e.g., '1,2,5')")
    
    args = parser.parse_args()
    
    try:
        vuln_indices = [int(x.strip()) for x in args.fuzz_indices.split(',')]
    except ValueError:
        print("Error: fuzz_indices must be a comma-separated list of integers.")
        sys.exit(1)

    # 2. Generate and compile wrappers
    vuln_name = os.path.basename(args.vuln_path)
    for idx in vuln_indices:
        if idx < 1 or idx > args.total_args:
            print(f"Warning: Index {idx} is out of bounds (1-{args.total_args}). Skipping.")
            continue
            
        wrapper_name = f"{vuln_name}_wrapper_arg{idx}"
        source_file = f"{wrapper_name}.c"
        
        print(f"[+] Generating {source_file} (Fuzzing Arg {idx})...")
        code = generate_wrapper_code(args.vuln_path, args.total_args, idx)
        
        with open(source_file, "w") as f:
            f.write(code)
            
        print(f"[+] Compiling {wrapper_name}...")
        try:
            # Check for gcc or clang
            compiler = "gcc"
            # Simple check if gcc exists could be added here, but subprocess will raise if not found
            subprocess.check_call([compiler, source_file, "-o", wrapper_name, "-fno-stack-protector", "-z", "execstack", "-no-pie", "-g"])
            print(f"    Success.")
            
            # Generate run script
            run_script_name = f"run_{wrapper_name}.sh"
            to_run.append(run_script_name)
            run_cmd = f"python afl_fuzzer.py -b ./{wrapper_name} -i seeds -o {wrapper_name}_findings -t 60 -r {wrapper_name}_crash_report.json"
            with open(run_script_name, "w") as f:
                f.write("#!/bin/bash\n")
                f.write(run_cmd + "\n")
            print(f"    [+] Created run script: {run_script_name}")
            
        except FileNotFoundError:
             print(f"    Error: '{compiler}' not found. Please ensure a C compiler is installed and in your PATH.")
        except subprocess.CalledProcessError as e:
            print(f"    Error compiling {wrapper_name}: {e}")
    
    for script in to_run:
        #result = subprocess.run(["bash", script], capture_output=True, text=True, check=True)
        result = os.system(f"bash {script}")
        #print(f"[+] {result}")

# python afl_fuzzer.py -b ./fuzz_wrapper  -i seeds -o findings -t 200

if __name__ == "__main__":
    main()
