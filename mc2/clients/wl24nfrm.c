/* $Id: wl24nfrm.c,v 1.3 2003/07/06 16:40:48 jal2 Exp $ */

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

#include <linux/version.h>

#ifdef MODULE
# if CONFIG_MODVERSIONS == 1
# include <linux/modversions.h>
# endif
#define __NO_VERSION__    //wl24n_cs.c includes linux/module.h
#include <linux/module.h>
#endif


#include <linux/config.h>

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/sysrq.h>

#include "wl24n.h"
#include "wl24nfrm.h"

/* ------------------------------------------------------------------------
 * RC4 en/decryption
 * ------------------------------------------------------------------------ */

typedef struct
        {
          u8 state[256];
          u8 x, y;
        } rc4ctx_t;

static void swap_byte(u8 *pA, u8 *pB)
{
  u8 Tmp;

  Tmp = *pA; *pA = *pB; *pB = Tmp;
}

void rc4_init(rc4ctx_t *pContext, unsigned char *pKey, int keylen)
{
  u8 index1, index2, *state;
  short counter;

  state = pContext->state;
  for (counter = 0; counter < 256; counter++)
    state[counter] = counter;
  pContext->x = 0;
  pContext->y = 0;
  index1 = 0;
  index2 = 0;
  for (counter = 0; counter < 256; counter++)
  {
    index2 = (pKey[index1] + state[counter] + index2) % 256;
    swap_byte(state + counter, state + index2);

    index1 = (index1 + 1) % keylen;
  }
}

static void rc4_crypt(rc4ctx_t *pContext, unsigned char *pSrc, unsigned char *pDest, int len)
{
  u8 x, y, *state, xorIndex;
  short counter;

  x = pContext->x;
  y = pContext->y;

  state = pContext->state;
  for (counter = 0; counter < len; counter ++)
  {
    x = (x + 1) % 256;
    y = (state[x] + y) % 256;
    swap_byte(state + x, state + y);

    xorIndex = (state[x] + state[y]) % 256;

    *(pDest++) = *(pSrc++) ^ state[xorIndex];
  }
  pContext->x = x;
  pContext->y = y;
}

/* ------------------------------------------------------------------------
 * CRC32 computation, according to 802.11 polynom
 * ------------------------------------------------------------------------ */

static const u32 fcs32tab[256] =
{
  0x00000000L, 0x77073096L, 0xEE0E612CL, 0x990951BAL,
  0x076DC419L, 0x706AF48FL, 0xE963A535L, 0x9E6495A3L,
  0x0EDB8832L, 0x79DCB8A4L, 0xE0D5E91EL, 0x97D2D988L,
  0x09B64C2BL, 0x7EB17CBDL, 0xE7B82D07L, 0x90BF1D91L,
  0x1DB71064L, 0x6AB020F2L, 0xF3B97148L, 0x84BE41DEL,
  0x1ADAD47DL, 0x6DDDE4EBL, 0xF4D4B551L, 0x83D385C7L,
  0x136C9856L, 0x646BA8C0L, 0xFD62F97AL, 0x8A65C9ECL,
  0x14015C4FL, 0x63066CD9L, 0xFA0F3D63L, 0x8D080DF5L,
  0x3B6E20C8L, 0x4C69105EL, 0xD56041E4L, 0xA2677172L,
  0x3C03E4D1L, 0x4B04D447L, 0xD20D85FDL, 0xA50AB56BL,
  0x35B5A8FAL, 0x42B2986CL, 0xDBBBC9D6L, 0xACBCF940L,
  0x32D86CE3L, 0x45DF5C75L, 0xDCD60DCFL, 0xABD13D59L,
  0x26D930ACL, 0x51DE003AL, 0xC8D75180L, 0xBFD06116L,
  0x21B4F4B5L, 0x56B3C423L, 0xCFBA9599L, 0xB8BDA50FL,
  0x2802B89EL, 0x5F058808L, 0xC60CD9B2L, 0xB10BE924L,
  0x2F6F7C87L, 0x58684C11L, 0xC1611DABL, 0xB6662D3DL,
  0x76DC4190L, 0x01DB7106L, 0x98D220BCL, 0xEFD5102AL,
  0x71B18589L, 0x06B6B51FL, 0x9FBFE4A5L, 0xE8B8D433L,
  0x7807C9A2L, 0x0F00F934L, 0x9609A88EL, 0xE10E9818L,
  0x7F6A0DBBL, 0x086D3D2DL, 0x91646C97L, 0xE6635C01L,
  0x6B6B51F4L, 0x1C6C6162L, 0x856530D8L, 0xF262004EL,
  0x6C0695EDL, 0x1B01A57BL, 0x8208F4C1L, 0xF50FC457L,
  0x65B0D9C6L, 0x12B7E950L, 0x8BBEB8EAL, 0xFCB9887CL,
  0x62DD1DDFL, 0x15DA2D49L, 0x8CD37CF3L, 0xFBD44C65L,
  0x4DB26158L, 0x3AB551CEL, 0xA3BC0074L, 0xD4BB30E2L,
  0x4ADFA541L, 0x3DD895D7L, 0xA4D1C46DL, 0xD3D6F4FBL,
  0x4369E96AL, 0x346ED9FCL, 0xAD678846L, 0xDA60B8D0L,
  0x44042D73L, 0x33031DE5L, 0xAA0A4C5FL, 0xDD0D7CC9L,
  0x5005713CL, 0x270241AAL, 0xBE0B1010L, 0xC90C2086L,
  0x5768B525L, 0x206F85B3L, 0xB966D409L, 0xCE61E49FL,
  0x5EDEF90EL, 0x29D9C998L, 0xB0D09822L, 0xC7D7A8B4L,
  0x59B33D17L, 0x2EB40D81L, 0xB7BD5C3BL, 0xC0BA6CADL,
  0xEDB88320L, 0x9ABFB3B6L, 0x03B6E20CL, 0x74B1D29AL,
  0xEAD54739L, 0x9DD277AFL, 0x04DB2615L, 0x73DC1683L,
  0xE3630B12L, 0x94643B84L, 0x0D6D6A3EL, 0x7A6A5AA8L,
  0xE40ECF0BL, 0x9309FF9DL, 0x0A00AE27L, 0x7D079EB1L,
  0xF00F9344L, 0x8708A3D2L, 0x1E01F268L, 0x6906C2FEL,
  0xF762575DL, 0x806567CBL, 0x196C3671L, 0x6E6B06E7L,
  0xFED41B76L, 0x89D32BE0L, 0x10DA7A5AL, 0x67DD4ACCL,
  0xF9B9DF6FL, 0x8EBEEFF9L, 0x17B7BE43L, 0x60B08ED5L,
  0xD6D6A3E8L, 0xA1D1937EL, 0x38D8C2C4L, 0x4FDFF252L,
  0xD1BB67F1L, 0xA6BC5767L, 0x3FB506DDL, 0x48B2364BL,
  0xD80D2BDAL, 0xAF0A1B4CL, 0x36034AF6L, 0x41047A60L,
  0xDF60EFC3L, 0xA867DF55L, 0x316E8EEFL, 0x4669BE79L,
  0xCB61B38CL, 0xBC66831AL, 0x256FD2A0L, 0x5268E236L,
  0xCC0C7795L, 0xBB0B4703L, 0x220216B9L, 0x5505262FL,
  0xC5BA3BBEL, 0xB2BD0B28L, 0x2BB45A92L, 0x5CB36A04L,
  0xC2D7FFA7L, 0xB5D0CF31L, 0x2CD99E8BL, 0x5BDEAE1DL,
  0x9B64C2B0L, 0xEC63F226L, 0x756AA39CL, 0x026D930AL,
  0x9C0906A9L, 0xEB0E363FL, 0x72076785L, 0x05005713L,
  0x95BF4A82L, 0xE2B87A14L, 0x7BB12BAEL, 0x0CB61B38L,
  0x92D28E9BL, 0xE5D5BE0DL, 0x7CDCEFB7L, 0x0BDBDF21L,
  0x86D3D2D4L, 0xF1D4E242L, 0x68DDB3F8L, 0x1FDA836EL,
  0x81BE16CDL, 0xF6B9265BL, 0x6FB077E1L, 0x18B74777L,
  0x88085AE6L, 0xFF0F6A70L, 0x66063BCAL, 0x11010B5CL,
  0x8F659EFFL, 0xF862AE69L, 0x616BFFD3L, 0x166CCF45L,
  0xA00AE278L, 0xD70DD2EEL, 0x4E048354L, 0x3903B3C2L,
  0xA7672661L, 0xD06016F7L, 0x4969474DL, 0x3E6E77DBL,
  0xAED16A4AL, 0xD9D65ADCL, 0x40DF0B66L, 0x37D83BF0L,
  0xA9BCAE53L, 0xDEBB9EC5L, 0x47B2CF7FL, 0x30B5FFE9L,
  0xBDBDF21CL, 0xCABAC28AL, 0x53B39330L, 0x24B4A3A6L,
  0xBAD03605L, 0xCDD70693L, 0x54DE5729L, 0x23D967BFL,
  0xB3667A2EL, 0xC4614AB8L, 0x5D681B02L, 0x2A6F2B94L,
  0xB40BBE37L, 0xC30C8EA1L, 0x5A05DF1BL, 0x2D02EF8DL
};

static u32 fcs32blk(u32 initializer, void* pBlk, int len)                                /* Laenge des Blocks            */
{ 
  u32 crc;

  crc = initializer;
  while(len--)
  {
    crc = (crc >> 8) ^ fcs32tab[(crc ^ *((u8*)pBlk)++) & 0xff];
  }

  return crc;
}

/* ------------------------------------------------------------------------
 * fill data buffer from source with given offset at beginning
 * ------------------------------------------------------------------------ */

void wl24fill(databuffer_t *pbuffer, char *psrc, int length, int offset)
{
  if (length + offset < (int)sizeof(pbuffer->buffer))
  {
    pbuffer->offset = offset;
    memcpy(pbuffer->buffer + offset, psrc, pbuffer->length = length);
  }
}

/* ------------------------------------------------------------------------
 * copy data out of buffer
 * ------------------------------------------------------------------------ */

void wl24drain(databuffer_t *pbuffer, char *pdest)
{
  memcpy(pdest, pbuffer->buffer + pbuffer->offset, pbuffer->length);
}

/* ------------------------------------------------------------------------
 * encrypt frame according to rules in pState.  Adjust length, which means
 * increasing it by 8 for IV+ICV fields.
 * ------------------------------------------------------------------------ */

int wl24encrypt(databuffer_t *pbuffer, Wlwepstate_t *pState)
{
  int headerlen, payloadlen, keylen;
  unsigned char rc4key[3 + WEP_MAXLEN];
  rc4ctx_t ctx;
  u32 icv;
  char *pBuf = pbuffer->buffer + pbuffer->offset;

  /* compute length of 802.11 header */

  headerlen = ((pBuf[1] & 3) == 3) ? 30 : 24;
  payloadlen = pbuffer->length - headerlen;
  if (payloadlen < 0)
    return -EINVAL;

  /* make space for IV+ICV field */

  memmove(pBuf - 4, pBuf, headerlen);
  pBuf -= 4;
  pbuffer->offset -= 4;
  pbuffer->length += 4;
  
  /* insert IV and key index */

  pBuf[headerlen    ] = (pState->ivval      ) & 0xff;
  pBuf[headerlen + 1] = (pState->ivval >>  8) & 0xff;
  pBuf[headerlen + 2] = (pState->ivval >> 16) & 0xff;
  pBuf[headerlen + 3] = pState->txkeyid;
  
  /* increment IV for next frame.  here we should skip over the 'weak'
     IVs for WEPplus */

  pState->ivval++;

  /* append ICV to plain data */

  icv = fcs32blk(0xffffffff, pBuf + headerlen + 4, payloadlen);
  icv = icv ^ 0xffffffff;
  pBuf[headerlen + 4 + payloadlen] = (icv      ) & 0xff;
  pBuf[headerlen + 5 + payloadlen] = (icv >>  8) & 0xff;
  pBuf[headerlen + 6 + payloadlen] = (icv >> 16) & 0xff;
  pBuf[headerlen + 7 + payloadlen] = (icv >> 24) & 0xff;
  payloadlen += 4;
  pbuffer->length += 4;

  /* construct key for RC4 algorithm */

  memcpy(rc4key, pBuf + headerlen, 3);
  keylen = pState->wepkeys[pState->txkeyid].length;
  memcpy(rc4key + 3, pState->wepkeys[pState->txkeyid].value, keylen);
  keylen += 3;

  /* set up RC4 algorithm */

  rc4_init(&ctx, rc4key, keylen);

  /* encrypt data payload + ICV */

  rc4_crypt(&ctx, pBuf + headerlen + 4, pBuf + headerlen + 4, payloadlen);

  /* clean up */

  memset(&ctx, 0, sizeof(ctx));

  /* set WEP bit in header */

  pBuf[1] |= WEPBIT;

  return 0;
}

/* ------------------------------------------------------------------------
 * decrypt frame according to rules in pState.  Adjust length, which means
 * increasing it by 8 for IV+ICV fields.  return whether CRC matched or not
 * ------------------------------------------------------------------------ */

int wl24decrypt(databuffer_t *pbuffer, Wlwepstate_t *pState)
{
  int headerlen, payloadlen, keyidx, keylen;
  unsigned char rc4key[3 + WEP_MAXLEN];
  rc4ctx_t ctx;
  u32 icv;
  char *pBuf = pbuffer->buffer + pbuffer->offset;

  /* compute length of 802.11 header. Check for presence of at least IV
     and ICV. */

  headerlen = ((pBuf[1] & 3) == 3) ? 30 : 24;
  payloadlen = pbuffer->length - headerlen - 8;
  if (payloadlen < 0)
    return -EINVAL;

  /* build up RC4 key */

  memcpy(rc4key, pBuf + headerlen, 3);
  keyidx = pBuf[headerlen + 3] & 3;
  keylen = pState->wepkeys[keyidx].length;
  memcpy(rc4key + 3, pState->wepkeys[keyidx].value, keylen);
  keylen += 3;

  /* set up RC4 algorithm */

  rc4_init(&ctx, rc4key, keylen);

  /* decrypt data payload + ICV */

  rc4_crypt(&ctx, pBuf + headerlen + 4, pBuf + headerlen + 4, payloadlen + 4);

  /* clean up */

  memset(&ctx, 0, sizeof(ctx));

  /* check ICV */

  icv = fcs32blk(0xffffffff, pBuf + headerlen + 4, payloadlen + 4);
  if (icv != 0xdebb20e3)
    return -EFAULT;

  /* remove IV + ICV, adjust length */

  memmove(pBuf + 4, pBuf, headerlen); pBuf += 4;
  pbuffer->offset += 4;
  pbuffer->length -= 8;
 
  /* clear WEP bit in header */

  pBuf[1] &= ~WEPBIT;

  return 0;
}

/* ------------------------------------------------------------------------
 * unpack 802.11 frame to 802.3 according to llctype.
 * returns offset of 802.3 frame, reduce length
 * ------------------------------------------------------------------------ */

int wl24unpack(databuffer_t *pbuffer, int llctype)
{
  int headerlen, payloadlen;
  char dest[6], src[6];
  unsigned snaptype;
  unsigned char dsap, ssap;
  char *pBuf = pbuffer->buffer + pbuffer->offset;

  headerlen = ((pBuf[1] & 3) == 3) ? 30 : 24;
  payloadlen = pbuffer->length - headerlen;
  if (payloadlen < 0)
    return -EFAULT;

  /* WaveLan LLC: convert 802.11 header to 802.3 */

  if (llctype == LLCType_WaveLan)
  {
    /* save addresses : Dst = A3(ToDS=1) or A1(ToDS=0)... */

    memcpy(dest, (pBuf[1] & 1) ? (pBuf + 16) : (pBuf + 4), 6);

    /* ...Src = A2(FromDS=0), otherwise A3(ToDS=0) or A4(ToDS=1) */

    memcpy(src, (pBuf[1] & 2) ? ((pBuf[1] & 1) ? (pBuf + 24) : (pBuf + 16)) : (pBuf + 10), 6);

    /* is this a SNAP frame ? Note we must not strip the SNAP
       header if the SNAP type is less than 1500, since this 
       would otherwise be interpreted as a length! */

    dsap = pBuf[headerlen]; 
    ssap = pBuf[headerlen + 1];
    if ((dsap == 0xaa) && (ssap == 0xaa))
    {
      snaptype = pBuf[headerlen + 6];
      snaptype = (snaptype << 8) | pBuf[headerlen + 7];
      if (snaptype > 1500)
      {
        memcpy(pBuf + headerlen - 6, dest, 6);
        memcpy(pBuf + headerlen    , src, 6);
        pbuffer->length -= (headerlen - 6);
        pbuffer->offset += (headerlen - 6);
        return 0;
      }
    }

    /* normal 802.x: insert dest, src, length before payload */

    memcpy(pBuf + headerlen - 14, dest, 6);
    memcpy(pBuf + headerlen -  8, src, 6);
    pBuf[headerlen - 2] = (payloadlen >> 8) & 0xff;
    pBuf[headerlen - 1] = payloadlen & 0xff;
    pbuffer->length -= (headerlen - 14);
    pbuffer->offset += (headerlen - 14);
    return 0;
  }

  /* simple 802.3 in 802.11: simply strip header */

  else
  {
    pbuffer->length -= headerlen;
    pbuffer->offset += headerlen;
    return 0;
  }
}

/* ------------------------------------------------------------------------
 * pack 802.3 frame to 802.11 according to llctype and network type.
 * ------------------------------------------------------------------------ */

void wl24pack(databuffer_t *pbuffer, int llctype, int ToDS, char *pBSSID)
{
  char dest[6], src[6];
  unsigned ethertype;
  char *pBuf;
  static char rfc1042_header[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00},
              ieee8021h_header[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8};

  /* extract frame parameters */

  pBuf = pbuffer->buffer + pbuffer->offset;
  memcpy(dest, pBuf, 6);
  memcpy(src, pBuf + 6, 6);

  /* 802.3 encapsulation? Then prepend 802.11 header */

  if (llctype == LLCType_IEEE_802_11)
  {
    pbuffer->offset -= 24;
    pbuffer->length += 24;
  }

  /* WaveLan encapsulation? */

  else
  {
    /* extract ethertype */
 
    ethertype = pBuf[12];
    ethertype = (ethertype << 8) | pBuf[13];

    /* 802.x frame, i.e. length/type field is length ? */

    if (ethertype <= 1500)
    {
      /* strip length and set length to actual length of payload+header.
         i.e. we strip potential slack area of data coming from Ethernet.
         The latter is necessary to assure a correct length field when
         the frame is reconstructed at the receiver side. */

      pbuffer->length = (ethertype + 14);
      pbuffer->offset -= 10; pbuffer->length += 10;
    }

    /* otherwise type, i.e. Ethernet II frame that has to be wrapped in
       SNAP */

    else
    {
      char *snapheader;
      int snaplen;

      /* insert SNAP header.  Note we have to use 802.1h for IPX with
         Ethernet II framing if we want to pass a WECA certification ;-) */

      if (ethertype == 0x8137)
      {
        snapheader = ieee8021h_header; snaplen = sizeof(ieee8021h_header);
      }
      else
      {
        snapheader = rfc1042_header; snaplen = sizeof(rfc1042_header);
      }
 
      pbuffer->offset += (12 - snaplen);
      pbuffer->length -= (12 - snaplen); 
      pBuf = pbuffer->buffer + pbuffer->offset;
      memcpy(pBuf, snapheader, snaplen);

      pbuffer->offset -= 24;
      pbuffer->length += 24;
    }
  }

  /* now fill in the 802.11 header */

  pBuf = pbuffer->buffer + pbuffer->offset;
  memset(pBuf, 0, 24);
  pBuf[0] = 0x08; /* data/data */
  memcpy(pBuf + 10, src, 6); /* A2 */
  if (ToDS)
  {
    pBuf[1] = 1; /* ToDS */
    memcpy(pBuf + 4, pBSSID, 6);
    memcpy(pBuf + 16, dest, 6);
  }
  else
  {
    memcpy(pBuf + 4, dest, 6);
    memcpy(pBuf + 16, pBSSID, 6);
  }
}
