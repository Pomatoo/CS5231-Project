#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>

int main(int argc, char* argv[]) {
    
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
    if (!fuzz_string) {
        close(fd);
        return 1;
    }
    
    // Read the file content INTO the buffer
    read(fd, fuzz_string, st.st_size);
    
    // IMPORTANT: Turn it into a valid C-String by adding NULL at the end
    fuzz_string[st.st_size] = '\0';
    
    close(fd);
    // ---------------------------------------------------------

    
    // Resolve absolute path to vuln binary
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd");
        return 1;
    }
    
    char vuln_path[PATH_MAX];
    snprintf(vuln_path, sizeof(vuln_path), "%s/../vuln_bins/five_args_vuln", cwd);
    

    // ---------------------------------------------------------
    // STEP 2: RUN THE BINARY (Pass the content as Arg2)
    // ---------------------------------------------------------
    char *new_argv[] = {
        vuln_path,   // argv[0]
        "A_1",   // argv[1] (STATIC)
        "A_2",   // argv[2] (STATIC)
        "A_3",   // argv[3] (STATIC)
        fuzz_string,  // argv[4] (FUZZED)
        "A_5",   // argv[5] (STATIC)
        NULL
    };

    // Replace current process with the target
    execv(new_argv[0], new_argv);
    perror("execv");

    return 0;
}
