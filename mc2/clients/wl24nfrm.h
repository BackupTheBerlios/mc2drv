/* $Id: wl24nfrm.h,v 1.2 2002/12/07 18:51:26 jal2 Exp $ */

/* ===========================================================    
    Copyright (C) 2002 Alfred Arnold alfred@ccac.rwth-aachen.de

    Portions of the source code are based on code by
    David A. Hinds under Copyright (C) 1999 David A. Hinds
    and on code by Jean Tourrilhes under
    Copyright (C) 2001 Jean Tourrilhes, HP Labs <jt@hpl.hp.com> 

    This software may be used and distributed according to the
    terms of the GNU Public License 2, incorporated herein by
    reference.
   =========================================================== */

#define WEP_CNT 4
#define WEP_MAXLEN 16 //jal: not 13 aka WEP_LARGE_KEY_SIZE ???

/* small and large key sizes for WEP64 / WEP128 */
#define WEP_SMALL_KEY_SIZE 5
#define WEP_LARGE_KEY_SIZE 13

typedef struct _Wlwepkey_t
{
  int length;
  unsigned char value[WEP_MAXLEN];
} Wlwepkey_t;

typedef struct _Wlwepstate_t
{
  Wlwepkey_t wepkeys[WEP_CNT];
  int encrypt, exclude_unencr;
  unsigned int txkeyid, ivval;
} Wlwepstate_t;

typedef struct _databuffer_t
{
  int offset, length;
  char buffer[2400];
} databuffer_t;

/* FrameControl bits, the 16 bit value is stored in LE order ! */

/* offset +1 */
#define WEPBIT        0x40 
#define MOREFRAGBIT   0x04
#define RETRYBIT      0x08

extern void wl24fill(databuffer_t *pbuffer, char *psrc, int length, int offset);

extern void wl24drain(databuffer_t *pbuffer, char *pdest);

extern int wl24encrypt(databuffer_t *pbuffer, Wlwepstate_t *pState);

extern int wl24decrypt(databuffer_t *pbuffer, Wlwepstate_t *pState);

extern int wl24unpack(databuffer_t *pbuffer, int llctype);

extern void wl24pack(databuffer_t *pbuffer, int llctype, int ToDS, char *pBSSID);
