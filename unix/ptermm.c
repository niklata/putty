/*
 * pterm main program.
 */

#include <stdio.h>

#include "putty.h"

Backend *select_backend(Config *cfg)
{
    return &pty_backend;
}

int cfgbox(Config *cfg)
{
    return 1;			       /* no-op in pterm */
}

int process_nonoption_arg(char *arg, Config *cfg)
{
    return 0;                          /* pterm doesn't have any. */
}

char *make_default_wintitle(char *hostname)
{
    return dupstr("pterm");
}

int main(int argc, char **argv)
{
    extern int pt_main(int argc, char **argv);
    extern void pty_pre_init(void);    /* declared in pty.c */

    cmdline_tooltype = TOOLTYPE_NONNETWORK;

    pty_pre_init();

    return pt_main(argc, argv);
}