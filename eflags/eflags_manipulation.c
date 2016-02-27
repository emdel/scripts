#include <stdio.h>
#include <stdlib.h>

/*
 * 
 * Simple script to understand the EFLAGS register behavior, 
 * when we try to overwrite it.
 * Have a look at the Intel manuals for more info.
 * 
 * TODO: 
 *  - Parse EFLAGS fields
 *
 * 2016 - emdel
 *
 */

int 
    main(int argc, char **argv)
{

    long eflags = 0;
    long counter = 0;
    unsigned long i;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s %s\n" , argv[0], "<counter>");
        exit(1);
    }

    counter = atoi(argv[1]);

    for(i = 0; i < counter; i++)
    {
        // trap flag check
        if(((i & 0x100) >> 8) == 1) 
        {
            printf("0x%lx,SKIPPED\n" , i);
            continue;
        }
        asm volatile (
            "nop\n\t" 
            "mov %1, %%rax\n\t"
            "push %%rax\n\t"
            "popfq\n\t"
            "pushfq\n\t"
            "pop %%rbx\n\t"
            "mov %%rbx, %0\n\t"
            "nop"
            :"=r"(eflags)
            :"r"(i)
            :"rax", "rbx"
            );
        printf("0x%lx,0x%lx\n" , i, eflags);
    }

return 0;
}
