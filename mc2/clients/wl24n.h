/* $Id: wl24n.h,v 1.3 2002/12/07 18:51:26 jal2 Exp $ */

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

/* The interface of wl24n.c to the PCMCIA module */

typedef u32 uint32;
typedef s32 int32;
typedef u16 uint16;
typedef u8   uint8;
typedef int bool;

#define assert(x) \
  if (!(x)) \
    printk(KERN_WARNING "#ERR assertion " #x " failed in " __FILE__ \
         " line %d\n", __LINE__)

#define MIN(x,y) ((x) < (y) ? (x) : (y))

#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

/* BSSType in ScanReq, module parameter network */
typedef enum {
  BSSType_Infrastructure = 0,
  BSSType_Independent = 1,
  BSSType_AnyBSS = 2
} BSSType_t;

typedef enum {
  ScanType_Active = 0,
  ScanType_Passive = 1
} ScanType_t;

typedef enum {
  AuthType_OpenSystem = 0,
  AuthType_SharedKey = 1
} AuthType_t;

/* module param LLCType */
typedef enum {
  LLCType_WaveLan = 1,
  LLCType_IEEE_802_11 = 2
} LLCType_t;

/* MibStatus (for ioctl's ?), values are a guess from the SDL diagrams */
typedef enum {
  Mib_Success = 0,
  Mib_Invalid = 1,
  Mib_WriteOnly = 2,
  Mib_ReadOnly = 3
} Mib_Status_t;

/* debug support */

/* bits in WL24Cb_t's dbg_mask */

#define DBG_PCMCIA_CALLS          0x00000001
#define DBG_PCMCIA_EVENTS         0x00000002
#define DBG_MSG_TO_CARD           0x00000004
#define DBG_MSG_FROM_CARD         0x00000008
#define DBG_STATES                0x00000010
#define DBG_INITIALIZATION        0x00000020
#define DBG_DEV_CALLS             0x00000040
#define DBG_CONNECTED_BSS         0x00000080
#define DBG_AUTH_BSS              0x00000100

/* if in WL24Cb_t's dbg_mask DBG_MSG_TO_CARD is set
   the WL24Cb_t's msg_to_card_dbg_mask controls which messages between
   driver and card do we see: */
#define DBG_SCAN_REQ              0x00000001
#define DBG_JOIN_REQ              0x00000002
#define DBG_AUTH_REQ              0x00000004
#define DBG_ASSOC_REQ             0x00000008
#define DBG_RESYNC_REQ            0x00000010
#define DBG_SITE_REQ              0x00000020
#define DBG_POWERMGT_REQ          0x00000040
#define DBG_DEAUTH_REQ            0x00000080
#define DBG_DISASSOC_REQ          0x00000100
#define DBG_GETMIB_REQ            0x00000200
#define DBG_SETMIB_REQ            0x00000400
#define DBG_RESET_REQ             0x00000800
#define DBG_TXDATA_REQ            0x00001000
#define DBG_START_REQ             0x00002000
#define DBG_TXDATA_REQ_DATA       0x00004000

/* if in WL24Cb_t's dbg_mask DBG_MSG_FROM_CARD is set
   the WL24Cb_t's msg_from_card_dbg_mask controls which messages
   from the card we do see: */
#define DBG_ALARM           0x00000001
#define DBG_MDCFM           0x00000002
#define DBG_MDIND           0x00000004 /* debug some info for MdInd's: DA,SA,RSSI,... */
#define DBG_MDIND_HEADER    0x00000008 /* plus the rx header */
#define DBG_MDIND_DATA      0x00000010 /* plus begin of data */
#define DBG_ASSOC_CFM       0x00000020
#define DBG_ASSOC_IND       0x00000040
#define DBG_AUTH_CFM        0x00000080
#define DBG_AUTH_IND        0x00000100
#define DBG_DEAUTH_CFM      0x00000200
#define DBG_DEAUTH_IND      0x00000400
#define DBG_DISASSOC_CFM    0x00000800
#define DBG_DISASSOC_IND    0x00001000
#define DBG_GET_CFM         0x00002000
#define DBG_JOIN_CFM        0x00004000
#define DBG_POWERMGT_CFM    0x00008000
#define DBG_REASSOC_CFM     0x00010000
#define DBG_REASSOC_IND     0x00020000
#define DBG_SCAN_CFM        0x00040000
#define DBG_SET_CFM         0x00080000
#define DBG_START_CFM       0x00100000
#define DBG_RESYNC_CFM      0x00200000
#define DBG_SITE_CFM        0x00400000
#define DBG_SAVE_CFM        0x00800000
#define DBG_RFTEST_CFM      0x01000000
#define DBG_FAILED_MDCFM    0x02000000
#define DBG_RX_FRAGMENTS    0x04000000 /* debug fragment re-assembly on rx */

/* trace support */

#define TRACE_MSG_SENT              1
#define TRACE_MSG_RCV               2
#define TRACE_NEW_STATE             3
#define TRACE_NEW_BSS_FOUND         4
#define TRACE_TRY_NEW_BSS           5

/* internal id for additional data records, don't use */
#define TRACE_DATA                 31

/* set to zero to disable trace, otherwise the number of trace records */
#define TRACE_NR_RECS 128


/* initializes the driver */
void *wl24n_card_init(uint32 dbg_mask, uint32 msg_to_dbg_mask,
          uint32 msg_from_dbg_mask,
          int BaseAddr, int irq, LLCType_t llctype, 
          BSSType_t bsstype, uint8 *ESSID, int ESSID_len,
          uint8 Channel, int *open_counter, char **dev_name, 
          uint32 trace_mask);

/* stops the driver */
void wl24n_card_stop(void *priv);

/* resets the card (returns 0 on failure) */
int wl24n_card_reset(void *priv);

/* stops the netif of the driver */
void wl24n_card_netif_stop(void *priv);

/* handle an interrupt from card */
void wl24n_interrupt(int irq, void *dev_id, struct pt_regs *regs);

/* remove/create proc dir stuff common for all driver instances */
void wl24n_remove_procdir(void);
void wl24n_create_procdir(void);

