/* $Id: wl24n_cs.h,v 1.2 2002/11/04 21:23:56 jal2 Exp $ */

/* ===========================================================    
    Copyright (C) 2002 Joerg Albert - joerg.albert@gmx.de
    Copyright (C) 2002 Alfred Arnold alfred@ccac.rwth-aachen.de

    Portions of the source code are based on code by
    David A. Hinds under Copyright (C) 1999 David A. Hinds
    and on code by Jean Tourrilhes under
    Copyright (C) 2001 Jean Tourrilhes, HP Labs <jt@hpl.hp.com> 

    This software may be used and distributed according to the
    terms of the GNU Public License 2, incorporated herein by
    reference.
   =========================================================== */

/* To keep PCMCIA separated from the core stuff, there are some procs
   in the PCMCIA part called from wl24n: */

/* checks if there is a link with this private data in the dev_list's mc2_priv.
   If not, return -ENODEV.
   Otherwise check if a release is pending (link->state & STALE_CONFIG)
   and trigger a timer for it. */
int wl24n_cs_close(void *priv);
