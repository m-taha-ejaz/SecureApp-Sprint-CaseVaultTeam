/* INTENTIONALLY VULNERABLE - LOCAL LAB ONLY; never compile into production. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char filename[24];
    strcpy(filename, argv[1]); /* CWE-120: unchecked copy into fixed buffer */
    printf("Legacy accepted: %s\n", filename);
    return 0;
}
