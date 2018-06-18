#include <stdio.h>
#include "sfmm.h"

int main(int argc, char const *argv[]) {

    sf_mem_init();
    void* a = sf_malloc(345);
    void *y  = sf_realloc(a,0);
    sf_blockprint(y-8);
    sf_mem_fini();
    return EXIT_SUCCESS;
}
