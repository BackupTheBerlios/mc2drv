/* $Id: wl24n.c,v 1.8 2003/01/05 15:26:33 jal2 Exp $ */
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

/* Trying to implement a driver for ELSA MC2 (Am79C930 + PRISM chipset) newly from
   scratch for 2.4 kernels. Based on ELSA's example.
   Skipped: PnP, flash loading

   all procedures called wl24* are called from extern */

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
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/ctype.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>          /* for enet_statistics */
#include <linux/etherdevice.h>
#include <linux/wait.h>               /* we need a waitqueue in ioctl() */
#include <linux/wireless.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>  /* for rtnl_lock() */
#include <linux/tty.h> /* for console_print */
#include <linux/proc_fs.h>

#include <linux/tqueue.h>

#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/delay.h>

#include "wl24n_cs.h" /* the i/f we use from the pcmcia part */
#include "wl24nfrm.h" /* 802.11 frame handling */
#include "wl24n.h" /* our own i/f */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0))
# error "kernel versions < 2.2.0 unsupported !!!"
#endif

// some adaptations for 2.2.x kernels
#ifndef DECLARE_WAIT_QUEUE_HEAD // if wait.h does not define this (2.2.13 doesn't has it, 2.2.19 has ...)
# ifndef init_waitqueue_head // somewhere between pcmcia-cs 3.1.22 and 3.1.30 D.H. introduced this
typedef struct wait_queue *wait_queue_head_t;
static inline void init_waitqueue_head(wait_queue_head_t *hd)
{
  *hd = NULL;
}
# endif
#endif

#define PACKED __attribute__((packed))

/* define this to use the task queue tq_immediate to run rx code */
//#define RX_USE_TASK_QUEUE

/* define to just dump the incoming data packets (if dbg_mask is
   correctly set!), but don't forward them to the host's stack */
//#define DEBUG_DONT_PROCESS_MDIND

/* undef to switch off all internal logging
   - each internal logging consumes performance. */
#define INTERNAL_LOG

/* def to disable debugging of msgs from card */
//#define DISABLE_DEBUG_RX_MSG

#ifdef INTERNAL_LOG
#define CHECK_ALLOC_TXBUF //trace allocation and free'ing of tx buffers
//#define LOG_COPY_PROCS //define to see copy procs
//#define LOG_DISABLE_INTERRUPT //disable_interrupt
//#define LOG_ENABLE_INTERRUPT
//#define LOG_INIT_ESBQ_TXBUF
//#define LOG_RESTART_CARD
//#define LOG_ALLOC_TXBUF
//#define LOG_FREE_TXBUF
//#define LOG_READ_RXBUF
//#define LOG_FREE_REQUESTS
//#define LOG_WL24N_WATCHDOG
//#define LOG_CFM_AVAIL
//#define LOG_CFM_DONE
//#define LOG_WL24N_RXINT
//#define LOG_FIND_MATCHING_BSS
//#define LOG_ADD_BSS_TO_SET
//#define LOG_STATE_IBSS_MDIND /* we got a MdInd in state IBSS or ESS */
//#define LOG_TXDATAREQ_INCOMING
//#define LOG_MDIND_NO_PAYLOAD
#define LOG_CARD_REMOVED
//#define LOG_FREQDOMAIN
//#define LOG_IWENCODE  /* log info on SIOC[GS]IWENCODE ioctl's */
//#define LOG_IWSPY
#define LOG_RX_FRAGMENTS /* log info on rx fragments */
#endif //#ifdef INTERNAL_LOG

/* we need <= 32 zeros to pass a dummy bssid and compare the SSID to it */
static const uint8 zeros[IW_ESSID_MAX_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                               0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/* IEEE802.11 defines */
#define SIZE_OF_SSID (1+1+32)

#define SZ_MAC_ADDR 6

/* defines for information element coding:
   1 byte ID, 1 byte length of information field, n bytes information field
   (see 7.3.2 in [1]) */
#define IE_ID_SSID 0              /* length 0 - 32 */
#define IE_ID_SUPPORTED_RATES 1
#define IE_ID_DS_PARAM_SET 3
#define IE_ID_CF_PARAM_SET 4
#define IE_ID_TIM 5
#define IE_ID_IBSS_PARAM_SET 6
#define IE_ID_CHALLENGE_TEXT 16

// MIB Attrib
#define aStationID                            0
#define aAuthenticationAlogrithms             1
#define aAuthenticationType                   2
#define aMediumOccupancyLimit                 3
#define aCFPollable                           4
#define aCFPPeriod                            5
#define aCFPMaxDuration                       6
#define aAuthenticationResponseTimeout        7
#define aReceiveDTIMs                         8
#define aPrivacyOptionImplemented             9
#define aPrivacyInvoked                      10
#define aWEPDefaultKeys                      11
#define aWEPDefaultKeyID                     12
#define aWEPKeyMappings                      13
#define aWEPKeyMappingLength                 14
#define aExcludeUnencrypted                  15
#define aWEPICVErrorCount                    16
#define aWEPUndecryptableCount               17
#define aWEPExcludedCount                    18
#define aMacAddress                          19
#define aGroup_Addresses                     20
#define aRTSThreshold                        21
#define aShortRetryLimit                     22
#define aLongRetryLimit                      23
#define aFragmentationThreshold              24
#define aMaxTransmitMSDULifetime             25
#define aMaxReceiveLifetime                  26
#define aManufacturerID                      27
#define aProductID                           28
#define aTransmittedFragmentCount            29
#define aMulticastTransmittedFrameCount      30
#define aFailedCount                         31
#define aReceiveFragmentCount                32
#define aMulticastReceivedCount              33
#define aFCSErrorCount                       34
#define aRetryCount                          35
#define aMultipleRetryCount                  36
#define aRTSSuccessCount                     37
#define aRTSFailureCount                     38
#define aACKFailureCount                     39
#define aFrameDuplicateCount                 40
#define aPHYType                             41
#define aRegDomainsSupport                   42
#define aCurrentRegDomain                    43
#define aSlotTime                            44
#define aCCATime                             45
#define aRxTxTurnaroundTime                  46
#define aTxPLCPDelay                         47
#define aRxTxSwitchTime                      48
#define aTxRampOnTime                        49
#define aTxRFDelay                           50
#define aSIFSTime                            51
#define aRxRFDelay                           52
#define aRxPLCPDelay                         53
#define aMACProcessingDelay                  54
#define aTxRampOffTime                       55
#define aPreambleLength                      56
#define aPLCPHeaderLength                    57
#define aMPDUDurationFactor                  58
#define aAirPropagationTime                  59
#define aTempType                            60
#define aCWmin                               61
#define aCWmax                               62
#define aSupportDataRatesTx                  63
#define aSupportDataRatesRx                  64
#define aMPDUMaxLength                       65
#define aSupportTxAntennas                   66
#define aCurrentTxAntenna                    67
#define aSupportRxAntennas                   68
#define aDiversitySupport                    69
#define aDiversitySelectionRx                70
#define aNumberSupportedPowerLevels          71
#define aTxPowerLevel1                       72
#define aTxPowerLevel2                       73
#define aTxPowerLevel3                       74
#define aTxPowerLevel4                       75
#define aTxPowerLevel5                       76
#define aTxPowerLevel6                       77
#define aTxPowerLevel7                       78
#define aTxPowerLevel8                       79
#define aCurrentTxPowerLevel                 80
#define aCurrentChannel                      81
#define aCCAModeSupported                    82
#define aCurrentCCAMode                      83
#define aEDThreshold                         84
#define aSynthesizerLocked                   85
#define aCurrentPowerState                   86
#define aDozeTurnonTime                      87
#define aRCR33                               88
#define aDefaultChannel                      89
#define aSSID                                90
#define aPowerMgmtEnable                     91
#define aNetworkCapability                   92
#define aRouting                             93

/* == CONFIGURATION == */

// tx watchdog timeout:
#define TX_TIMEOUT ((4000*HZ)/1000)

/* comment out to ignore tx timeouts */
#define RESET_ON_TX_TIMEOUT

/* == DEFINES of the PC Card firmware/hardware == */

/* see also "Am79C930" document by AMD, publication no. 20183, April 1997 */

#define SLOW_DOWN_IO __asm__ __volatile__("outb %al,$0x80")

#define InB(port)                 inb(port)
#ifdef SLOW_DOWN_IO
# define OutB(data, port)  outb_p((data),(port))
#else
# define OutB(data, port)  outb((data),(port))
#endif
#define OutB_P(data, port) outb_p((data),(port))
#define OutSB(port, addr, size) outsb((port), (addr), (size))


/* System Interface Registers (SIR space) */
#define NIC_GCR     ((uint8)0x00)   /* SIR0 - General Configuration Register */
#define NIC_BSS     ((uint8)0x01)   /* SIR1 - Bank Switching Select Register */
#define NIC_LMAL    ((uint8)0x02)   /* SIR2 - Local Memory Address Register [7:0] */
#define NIC_LMAH    ((uint8)0x03)   /* SIR3 - Local Memory Address Register [14:8] */
#define NIC_IODPA   ((uint8)0x04)   /* SIR4 - I/O Data Port A */
#define NIC_IODPB   ((uint8)0x05)   /* SIR5 - I/O Data Port B */
#define NIC_IODPC   ((uint8)0x06)   /* SIR6 - I/O Data Port C */
#define NIC_IODPD   ((uint8)0x07)   /* SIR7 - I/O Data Port D */


/* Bits in GCR */
#define GCR_SWRESET     ((uint8)0x80)
#define GCR_CORESET     ((uint8)0x40)
#define GCR_DISPWDN     ((uint8)0x20)
#define GCR_ECWAIT      ((uint8)0x10)
#define GCR_ECINT       ((uint8)0x08)
#define GCR_INT2EC      ((uint8)0x04)
#define GCR_ENECINT     ((uint8)0x02)
#define GCR_DAM         ((uint8)0x01)


/* Bits in BSS (Bank Switching Select Register) */
#define BSS_FPAGE0      0x20   /* Flash memory page0 */
#define BSS_FPAGE1      0x28
#define BSS_FPAGE2      0x30
#define BSS_FPAGE3      0x38
#define BSS_SPAGE0      0x00   /* SRAM page0 */
#define BSS_SPAGE1      0x08
#define BSS_SPAGE2      0x10
#define BSS_SPAGE3      0x18

typedef uint32 CardAddr_t; /* bit 23-16 contain BSS above */
typedef uint16 Card_Word_t;
typedef Card_Word_t CardSR0Addr_t; /* an address in first SRAM page */
static const Card_Word_t cwZero = 0;
static const uint8 zerob = 0;

#define CARDADDR_MASK_PAGE 0x380000
#define CARDADDR_MASK_OFFS 0x007fff

/* some interesting addresses in the card SRAM PAGE 0 (BSS_SPAGE0 == 0) */

/* read the selftest result from here (after writing a zero to it):
   a 'W' means OK and must be ack'ed with a 'A'/'H' at the same location */
#define WL_SELFTEST_ADDR 0x480

/* this struct describes the values from WL_SELFTEST_ADDR on: */
typedef struct {
  Card_Word_t selftest;
  Card_Word_t ESBQReqStartAddr;
  Card_Word_t reserved1;
  Card_Word_t ESBQReqSize; /* in byte */
  Card_Word_t ESBQCfmStartAddr;
  Card_Word_t reserved2;
  Card_Word_t ESBQCfmSize;
  Card_Word_t TxBufHead;
  Card_Word_t reserved3;
  Card_Word_t TxBufSize; /* size of area for txbuf in bytes */  
} PACKED Card_BufInfo_t;

/* these two addresses come from Heiko Kirschke's WL24 driver.
   Both fields are delimited by a char < ' ', not by \0. */
#define WL_CARDNAME           0x1A00 /* max. length 32 */
#define WL_FIRMWARE_DATE      0x1A40 /* max. length 32 */


/* flash addresses */
#define WL_FLASH_MAC   ((BSS_FPAGE3<<16) | 0x4000) /* six bytes */
#define WL_FREQ_DOMAIN ((BSS_FPAGE3<<16) | 0x4006) /* one byte */
#define WL_FW_VERSION  ((BSS_FPAGE0<<16) | 0x4004) /* two bytes */

/* message ids to/from the firmware */

/* Signals firmware -> driver */
#define Alarm_ID               0x00
#define MdConfirm_ID           0x01
#define MdIndicate_ID          0x02
#define AssocConfirm_ID        0x03
#define AssocIndicate_ID       0x04
#define AuthConfirm_ID         0x05
#define AuthIndicate_ID        0x06
#define DeauthConfirm_ID       0x07
#define DeauthIndicate_ID      0x08
#define DisassocConfirm_ID     0x09
#define DisassocIndicate_ID    0x0A
#define GetConfirm_ID          0x0B
#define JoinConfirm_ID         0x0C
#define PowermgtConfirm_ID     0x0D
#define ReassocConfirm_ID      0x0E
#define ReassocIndicate_ID     0x0F
#define ScanConfirm_ID         0x10
#define SetConfirm_ID          0x11
#define StartConfirm_ID        0x12
#define ResyncConfirm_ID       0x13
#define SiteConfirm_ID         0x14
#define SaveConfirm_ID         0x15
#define RFtestConfirm_ID       0x16

/* message ids driver -> firmware */
#define AssocRequest_ID       0x20
#define AuthRequest_ID        0x21
#define DeauthRequest_ID      0x22
#define DisassocRequest_ID    0x23
#define GetRequest_ID         0x24
#define JoinRequest_ID        0x25
#define PowermgtRequest_ID    0x26
#define ReassocRequest_ID     0x27
#define ScanRequest_ID        0x28
#define SetRequest_ID         0x29
#define StartRequest_ID       0x2A
#define MdRequest_ID          0x2B
#define ResyncRequest_ID      0x2C
#define SiteRequest_ID        0x2D
#define SaveRequest_ID        0x2E
#define RFtestRequest_ID      0x2F

//#define ResetRequest_ID     ??? /* ??? not found in old sw, only the struct */

/* ??? */
#define MmConfirm_ID          0x60
#define MmIndicate_ID         0x61

/* driver state machine */
/*
  STATE_INVALID
  STATE_SCANNING  we are scanning for an access point / IBSS or both
  STATE_JOINING   we are trying to join a selected (I)BSS (BSSset[currBSS])
  STATE_ASSOC     trying to associate with a selected BSS
  STATE_AUTH      trying to authenticate
  STATE_STARTING_IBSS trying to start own IBSS 
  STATE_JOINED_IBSS   we joined an IBSS
  STATE_STARTED_IBSS  we started an IBSS
  STATE_JOINED_ESS  we joined an ESS
*/

/* forward definition of WL24Cb_t*/
struct _wl24cb_t;

/* type of a state function */
typedef void (*State_fct_t)(struct _wl24cb_t *, uint8, Card_Word_t);

/* forward decl. of state functions */
void state_invalid(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_scanning(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_starting_ibss(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_joining(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_assoc(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_auth(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_joined_ibss(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_started_ibss(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
void state_joined_ess(struct _wl24cb_t *cb, uint8 sigid, Card_Word_t msgbuf);
#ifdef WIRELESS_EXT
struct iw_statistics *wl24n_get_wireless_stats (struct net_device *dev);
#endif

/* a BSSDescription stores the values returned by a successful
   ScanConfirm (see 10.3.2.2.2 in [1]) in the WL24Cb_t (therefore not packed !)*/
typedef struct {
  uint8 valid; /* TRUE if entry is valid, FALSE otherwise */
  uint8 BSSID[6];
  uint8 SSID[SIZE_OF_SSID+1]; /* +1 for extra '\0' to make it printable */
  BSSType_t BSSType; /* value "AnyBSS" not possible here ! */
  uint16 BeaconPeriod;
  uint16 DTIMPeriod;
  uint8  Timestamp[8];
  uint8  LocalTime[8];
  uint8 PHYpset[3];
  uint8 CFpset[8];
  uint8 IBSSpset[4];
  uint16 CapabilityInfo;
  uint8 BSSBasicRateSet[10];
  uint8 ScanRSSI; /* RSSI returned by ScanCfm */
  uint8 MdIndRSSI; /* RSSI returned by last MdInd */
} BSSDesc_t;

/* the driver control block structure */
#define NR_BSS_DESCRIPTIONS 30
/* min channel time for scan req. */
#define SCAN_MIN_CHANNEL_TIME 100
/* max channel time for scan req. in first run */
#define SCAN_FIRST_RUN_MAX_CHANNEL_TIME 100
/* max channel time for scan req. in following runs */
#define SCAN_NEXT_RUN_MAX_CHANNEL_TIME 300

/* if the peer vanishes during a connection, we'll get MdConfirm with Status == 2 
   We implement kind of leaky bucket algorithm to determine when we re-scan for a better
   BSS. */
#define MDCFM_RESCAN_THRE   16 /* threshold when we will start rescan */
#define MDCFM_FAIL_PENALTY  1 /* penalty for each MdCfm failure */
#define MDCFM_OK_VALUE      2 /*  subtract this for a good MdCfm */
   
/* we do that many scans of all channels before we start our own IBSS
   if WL24Cb_t->bsstype != Infrastructure */
#define MAX_SCAN_RUNS_BEFORE_STARTING_IBSS 8

#define MAX_MIB_VALUE_SZ 100 /* a first guess */

/* values in Status field from card */
typedef enum {
  Status_Success = 0,
  Status_Invalid = 1,
  Status_Timeout = 2,
  Status_Refused = 3,
  Status_Many_Requests = 4,
  Status_AlreadyBSS = 5,
} Status_t;

/* status values in MdCfm */
typedef enum {
  StatusMdCfm_Success = 0,
  StatusMdCfm_NoBSS   = 1,
  StatusMdCfm_Fail    = 2,
  StatusMdCfm_AtimAck = 3,
  StatusMdCfm_AtimNak = 4,
  StatusMdCfm_Partial = 5,
} StatusMdCfm_t;


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  MibStatus;
  uint16  MibAttrib;
  uint8   MibValue[MAX_MIB_VALUE_SZ];
} PACKED GetCfm_t;

#if TRACE_NR_RECS > 0
# define TRACE_DATA_LEN 10
typedef struct {
  uint8 id;
  uint8 len; /* of data in byte */
  union {
    struct {
      uint32 jiffies;
      uint8 data[TRACE_DATA_LEN];
    } first;
    struct {
      uint8 data[TRACE_DATA_LEN+4];
    } follow;
  } u;
} PACKED TraceEntry_t;

#endif //#if TRACE_NR_RECS > 0

#ifdef CHECK_ALLOC_TXBUF
typedef struct {
  int used; /* != 0 if buffer is in use */
  long unsigned int jiffies; /* if used == 1, time when the buffer was allocated */
  Card_Word_t parent; /* if used == 1; the first buffer in the chain */
  uint8 sigid; /* if used == 1; the signal this buffer was allocated for */
} DbgTxBuf_t;
#endif

/* the descr. of a frequency domain */
typedef struct {
  uint16 code;
  char const *name;
  uint32 channel_map; /* if bit N is set, channel (N+1) is allowed */
  uint8 default_ch; /* default channel if parameter Channel is out of bound */
} FreqDomainDescr_t;

/* we spy on max. 8 mac addresses - undef and set to zero to disable and remove code 
   this define comes from linux/wireless.h */
//#undef IW_MAX_SPY
//#define IW_MAX_SPY 0

/* struct for iwspy tool */
typedef struct {
  uint8 spy_address[ETH_ALEN]; /* sender mac address to match */
  uint8 spy_level; /* RSSI of last packet received from sender */
  uint8 updated;   /* updated since last read out */
} Wlspy_t;

#define MAX_RXDATA_SIZE 2600
#define NR_RX_FRAG_CACHES 3 /* how many of these caches have we got 
                               (minimum 3 acc. to standard) */
typedef struct {
  uint8 addr2[ETH_ALEN];
  uint8 frag_nr;
  uint8 in_use; /* set to 0 if entry is empty */
  uint16 seq_nr; /* sequence and fragment nr from the sequence control field */
  uint16 buf_len; /* how many bytes are filled in buf */
  uint32 last_update; /* jiffies when buf was updated for the last time */
  uint8 buf[MAX_RXDATA_SIZE]; /* data buffer, will start with net data, no header */
} RxFragCache_t;

typedef struct _wl24cb_t {
  struct net_device *netdev;
  struct net_device_stats stats;
  int card_started;  /* != 0 if restart_card was successful */
  int *open_counter; /* points to link->open from pcmcia, which counts
                        the number of succ. open's (minus the close's) */
#ifdef WIRELESS_EXT
  struct iw_statistics  wstats;   // wireless stats
#endif /* WIRELESS_EXT */
  
  wait_queue_head_t waitq; /* to delay processes on ioctl calls */
  struct semaphore ioctl_mutex; /* to serialize ioctl() calls */

  char *name; /* name of the driver instance */
  /* see wl24n.h for bit definitions, set in init() */
  uint32 dbg_mask; /* bit mask to switch debugs on */
  uint32 msg_from_dbg_mask;
  uint32 msg_to_dbg_mask; /* bit mask for msgs to/from firmware,
                             used if DBG_MSG_WITH_CARD is set in dbg_mask */

  int BaseAddr; /* base address of IO register of card */
  uint8 MacAddress[SZ_MAC_ADDR]; /* MAC address read 
                                    from flash after firmware init */
  uint8 FreqDomain; /* frequency domain read from flash after firmware init */
  FreqDomainDescr_t const *frdesc; /* description of freq. domain */
  uint8 FWversion[2]; /* firmware version read from flash after firmware init */
  char  CardName[32+1];
  char  FirmwareDate[32+1];
  LLCType_t llctype; /* Wavelan or IEEE802_11, passed in init() */
  BSSType_t bsstype; /* Infrastructure, Independent (adhoc) or Any,
                        passed to init() */
  uint8 ESSID[SIZE_OF_SSID+1];  /* ESSID passed to init(), +1 for \0 to make it a C string */
  uint8 Channel;    /* channel passed to init() */

  int scan_runs; /* counts how often we scanned the air */
  int currBSS; /* index in BSSset for BSS we are currently trying to join or
                  we are synched to */
  BSSDesc_t BSSset[NR_BSS_DESCRIPTIONS]; /* BSS found by scans */

  int last_mibcfm_valid; /* signal by the ISR that a MIBCfm (get or set) has arrived */
  GetCfm_t last_mibcfm; /* the content of the last GetCfm or SetCfm from card 
                           (SetCfm_t matches the begin of GetCfm_t !) */

  State_fct_t state; /* current state of driver's state machine */

  Card_Word_t FreeTxBufStart; /* start and end of txbuf area in card memory */
  Card_Word_t FreeTxBufEnd;

  Card_Word_t  FreeTxBufList; /* anchor to linked list of free txbuf */
  Card_Word_t  FreeTxBufTail; /* points to last txbuf in free list */
  uint16       FreeTxBufLen;  /* number of txbuf in free list */

  Card_Word_t  ESBQReqStart;  /* start of ESBQ area for requests to firmware */
  Card_Word_t  ESBQReqEnd;    /* end of  -"- */
  Card_Word_t  ESBQReqHead;   /* next ESBQ to use for request to firmware */
  Card_Word_t  ESBQReqTail;   /* last ESBQ request which was given back
                                 from firmware to driver after processing it */
  Card_Word_t    ESBQCfmStart; /* start of ESBQ area for confirms from 
                                  firmware */
  Card_Word_t    ESBQCfmEnd;   /* end of -"- */
  Card_Word_t    ESBQCfm;

  struct proc_dir_entry *pdir; /* directory <N> under /proc/driver/mc2 */

  int           mdcfm_failure;

#if TRACE_NR_RECS > 0
  spinlock_t trace_spinlock;
  int trace_nr;       /* total nr of trace records written */
  int trace_next;     /* index to write next trace entry to */
  TraceEntry_t trace[TRACE_NR_RECS];
#endif
  uint32 trace_mask;  /* what shall we trace: trace event n, 
                         if n-th bit in mask is set */

  uint32 proc_read_bss_idx;  /* two counter used in proc_read_bss/_trace */
  uint32 proc_read_trace_idx;
#ifdef CHECK_ALLOC_TXBUF
  DbgTxBuf_t *dbg_txbuf;
  int dbg_chk_txbuf_print; /* if set to 1, printk warning about inconsistencies */
#endif

  /* we store the length of data in each chain of tx buffers
     in this array, where the index is the number of the first tx buffer of
     the chain in the tx buffer area */
  int txbuf_len_list_len; /* length of list below */
  uint16 *txbuf_len_list; /* array with element for each txbuf, stores the last
                             tx len when this buffer was the first one in the
                             chain */

  int was_restarted; /* set to 1 by restart_card,
                        used in wl24n_rxint to recognizes if any 
                        state procedure has resetted the
                        card and we don't need to call cfm_done */

  char nickname[IW_ESSID_MAX_SIZE+1]; /* nickname set & get only by 
                                         wireless tools */

#if IW_MAX_SPY > 0
  int iwspy_number; /* number of valid entries in iwspy[] below */
  Wlspy_t  iwspy[IW_MAX_SPY];
#endif

  /* the cache of received rx fragments */
  RxFragCache_t rx_cache[NR_RX_FRAG_CACHES];

  Wlwepstate_t wepstate;
  databuffer_t databuffer;
  uint8 cardmode; /* 'H' for kind of "raw" mode where we set the
                     I802.11 header, which allows to implement WEP
                     in the driver (firmware >= 2.06 needed)
                     'A' for the mode, where the firmware sets the
                     header.
                     This char is written into WL_SELFTEST_ADDR at startup. */

  uint8 match_wanted_bssid; /* if != 0 a BSS must match the wanted_bssid below
                               to be chosen */
  uint8 wanted_bssid[ETH_ALEN]; /* if match_wanted_bssid != 0, this is
                                   the wanted BSSID to join */
} WL24Cb_t;


/* forward decl. */
struct net_device_stats *wl24n_get_stats (struct net_device *dev);
int wl24n_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
void wl24n_watchdog(struct net_device *dev);
int wl24n_init(struct net_device *dev);
int wl24n_open(struct net_device *dev);
int wl24n_close(struct net_device *dev);
void wl24n_rxint(void *cb);
void create_proc_entries(WL24Cb_t *cb);
void delete_proc_entries(WL24Cb_t *cb);

/* defines for the 4th param below */
#define COPY_SLOW 1
#define COPY_FAST 0
static void copy_from_card(void *dest, CardAddr_t src, 
                           size_t size, int slow, WL24Cb_t *cb);


bool ScanReq(WL24Cb_t *cb, uint16 min_channel_time,
             uint16 max_channel_time, BSSType_t bsstype,
             ScanType_t scantype);

bool SetMIBReq(WL24Cb_t *cb, uint16 attr, void *src, size_t sz);
bool GetMIBReq(WL24Cb_t *cb, uint16 attrib);
//bool ResetReq(WL24Cb_t *cb, bool SetDefaultMIB, uint8 *macAddr);
bool SiteReq(WL24Cb_t *cb);


/* struct of a single tx buffer */
#define CARD_TXBUF_DATA_SIZE 254
typedef struct {
  Card_Word_t next;
  uint8 data[CARD_TXBUF_DATA_SIZE];
} PACKED Card_TxBuf_t;

/* the max size of one buffer in the chain at MdInd.Data */
#define CARD_RXBUF_SIZE 256

/* == PROC getFreqDomainDescr == */
FreqDomainDescr_t const *getFreqDomainDescr(uint16 code)
{
  static FreqDomainDescr_t const fd_tab[] = {
    {0x10, "FCC", 0x7ff, 10},
    {0x20, "IC", 0x7ff, 10},
    {0x30, "ETSI", 0x1fff, 10},
    {0x31, "Spain", 0x600, 10},
    {0x32, "France", 0x1e00, 10},
    {0x40, "MKK", 0x2000, 14},
  };
  static int const tab_len = sizeof(fd_tab) / sizeof(FreqDomainDescr_t);

  /* use this if an unknown code comes in */
  static FreqDomainDescr_t const unknown = 
  {0, "<unknown>", 0xffffffff, 10};
  
  int i;

  for(i=0; i < tab_len; i++)
    if (code == fd_tab[i].code)
      break;
  
  return (i >= tab_len) ? &unknown : &fd_tab[i];
} /* getFreqDomainDescr */


#ifdef CHECK_ALLOC_TXBUF
/* == PROC check_buf_addr == */
int check_buf_addr(WL24Cb_t *cb, char const *str1, 
                   char const *str2, Card_Word_t buf)
{
  int idx;
  if (buf < cb->FreeTxBufStart || buf >= cb->FreeTxBufEnd) {
    if (cb->dbg_chk_txbuf_print) {
      printk(KERN_WARNING "%s %s: %s addr x%x out of txbuf area (x%x-x%x)\n",
             cb->name, str1, str2, buf, cb->FreeTxBufStart,
             cb->FreeTxBufEnd-1);
      cb->dbg_chk_txbuf_print--;
      return 0;
    }
  }

  idx = (buf - cb->FreeTxBufStart) / sizeof(Card_TxBuf_t);
  if ((cb->FreeTxBufStart + idx * sizeof(Card_TxBuf_t)) != buf) {
    if (cb->dbg_chk_txbuf_print) {
      printk(KERN_WARNING "%s %s: %s addr x%x not on boundary (x%x-x%x,x%x)\n",
             cb->name, str1, str2, buf, cb->FreeTxBufStart,
             cb->FreeTxBufEnd-1, sizeof(Card_TxBuf_t));
      cb->dbg_chk_txbuf_print--;
      return 0;
    }
  }

  return 1;
} /* check_buf_addr */


/* == PROC dbg_txbuf_set_sigid == 
  sets the sigid after a dbg_txbuf_mark was called */
void dbg_txbuf_set_sigid(WL24Cb_t *cb, Card_Word_t buf, uint8 sigid)
{
  if (check_buf_addr(cb, __FUNCTION__, "buf", buf)) {
    int i = (buf - cb->FreeTxBufStart) / sizeof(Card_TxBuf_t);
    cb->dbg_txbuf[i].sigid = sigid;
  }
} /* dbg_txbuf_set_sigid */


/* == PROC dbg_txbuf_mark ==
   marks a buffer as used or free in the cb->dbg_txbuf array */
int dbg_txbuf_mark(WL24Cb_t *cb, Card_Word_t buf, int used, Card_Word_t parent)
{
  int idx;

  if (!check_buf_addr(cb, __FUNCTION__, "buf", buf))
    return 0;

  /* ignore parent if used == 0, i.e. if the buffer is free'd */
  if (used)
    if (!check_buf_addr(cb, __FUNCTION__, "parent", parent))
      return 0;

  idx = (buf - cb->FreeTxBufStart) / sizeof(Card_TxBuf_t);

  if (used) {
    if (cb->dbg_txbuf[idx].used) {

      if (cb->dbg_chk_txbuf_print) {
        printk(KERN_WARNING "%s: %s buf x%x in use: alloced %lu ticks before , parent x%x sigid x%x\n", 
               cb->name, __FUNCTION__, buf, jiffies - cb->dbg_txbuf[idx].jiffies,
               cb->dbg_txbuf[idx].parent, cb->dbg_txbuf[idx].sigid);
        if (check_buf_addr(cb, __FUNCTION__, "parent", cb->dbg_txbuf[idx].parent)) {
          Card_Word_t parent = cb->dbg_txbuf[idx].parent;
          int i = (parent - cb->FreeTxBufStart) / sizeof(Card_TxBuf_t);
          if (cb->dbg_txbuf[i].used) {
            printk(KERN_WARNING "%s: %s parent x%x: used, alloced %lu ticks before, parent x%x, sigid x%x\n",
                   cb->name, __FUNCTION__, parent, 
                   jiffies - cb->dbg_txbuf[i].jiffies, cb->dbg_txbuf[i].parent,
                   cb->dbg_txbuf[i].sigid);
          } else {
            printk(KERN_WARNING "%s: %s parent x%x: free\n",
                   cb->name, __FUNCTION__, parent);
          }
        }
        cb->dbg_chk_txbuf_print--;
      } /* if (cb->dbg_chk_txbuf_print) */

      return 0;

    } else {

      cb->dbg_txbuf[idx].used = 1;
      cb->dbg_txbuf[idx].jiffies = jiffies;
      cb->dbg_txbuf[idx].parent = parent;
      cb->dbg_txbuf[idx].sigid = 0xfe;
      return 1;
    }
  } else {
    /* !used */
    if (!cb->dbg_txbuf[idx].used) {
      if (cb->dbg_chk_txbuf_print) {
        printk(KERN_WARNING "%s: %s buf x%x already free\n", 
               cb->name, __FUNCTION__, buf);
        cb->dbg_chk_txbuf_print--;
      }
      return 0;
    } else {
      cb->dbg_txbuf[idx].used = 0;
      return 1;
    }
  }
} /* dbg_txbuf_mark */
#endif //#ifdef CHECK_ALLOC_TXBUF


#if TRACE_NR_RECS > 0
  
/* == PROC trace_add_data ==
   adds data entries in the trace records.
   Must be called inside the trace spinlock. */
static void trace_add_data(WL24Cb_t *cb, uint8 *data, int len)
{
  TraceEntry_t *te = &cb->trace[cb->trace_next];

  while(len > 0) {
    te->id = TRACE_DATA;
    //te->len = MIN(len,TRACE_DATA_LEN+4);
    te->len = MIN(len,sizeof(te->u.follow.data));
    memcpy(te->u.follow.data,data,te->len);
    data += te->len;
    len -= te->len;

    cb->trace_nr++;
    if (++cb->trace_next >= TRACE_NR_RECS)
      cb->trace_next = 0;
  }
} /* trace_add_data */

/* == PROC trace_add == 
 adds a trace entry to the buffer */
static void trace_add(WL24Cb_t *cb, uint8 id, uint8 *data, int len)
{
  unsigned long flags;
  TraceEntry_t *te;

#if 0
  printk(KERN_DEBUG "%s %s: id %d len %d data: %02x %02x\n",
         cb->name, __FUNCTION__, id, len, data[0], data[1]);
#endif

  /* only trace if mask bit is set */
  if ((cb->trace_mask & (1 << id)) == 0)
    return;

  spin_lock_irqsave(&cb->trace_spinlock, flags);

  te = &cb->trace[cb->trace_next];
  te->id = id;
  te->u.first.jiffies = jiffies;
  te->len = MIN(len,sizeof(te->u.first.data));
  memcpy(te->u.first.data, data, te->len);

  cb->trace_nr++;
  if (++cb->trace_next >= TRACE_NR_RECS)
    cb->trace_next = 0;

  if (len > te->len)
    trace_add_data(cb,data+te->len,len-te->len);

  spin_unlock_irqrestore(&cb->trace_spinlock, flags);
} /* _trace_add */
#endif

/* == PROC dumpk == */
void dumpk(uint8 *addr, int sz)
{
  while (sz--)
    printk("%02x ",*addr++);
}

void dumpk2(uint8 *addr, int sz)
{
  int z;

  for (z = 0; z < sz; z++)
    {
      if ((z & 15) == 0)
        printk("%04x: ", z);
      printk("%02x ",*addr++);
      if ((z & 15) == 15)
        printk("\n");
    }
}

/* == PROC printc ==
   print to console   */
void printc(char const *fmt, ...)
{
  char buf[256];
  va_list ap;

  va_start(ap, fmt);

  vsprintf(buf,fmt,ap);
  console_print(buf);

  va_end(ap);
}

/* == PROC rateset2str ==
   transforms a rate set into a readable string: XX.X Mbit, */
char *rateset2str(uint8 *set, char *buf, int sz)
{
  int nr = set[1]; /* number of rates */
  char *p = buf;
  uint8 *r = set+2; /* first rate */
  int speed; /* in 500 kbit units */

  while (nr-- && p < (buf+sz-(sizeof("XX.XMbit ")+1))) {

    if (*r > 0x80) {
      speed = *r - 0x80;
      p += sprintf(p, "%d%sMbit ", speed/2,
                   speed % 2 ? ".5" : "");
    }
    r++;
  } /* while (nr-- ...) */

  return buf;
} /* rateset2str */


#if TRACE_NR_RECS > 0
/* == PROC sigid2str == 
  converts a signal id into a string.
  currently only used for trace output */
char *sigid2str(uint8 sigid)
{
  switch (sigid) {
  case Alarm_ID: return "Alarm";
  case MdConfirm_ID: return "MdConfirm";
  case MdIndicate_ID: return "MdIndicate";
  case AssocConfirm_ID: return "AssocConfirm";
  case AssocIndicate_ID: return "AssocIndicate";
  case AuthConfirm_ID: return "AuthConfirm";
  case AuthIndicate_ID: return "AuthIndicate";
  case DeauthConfirm_ID: return "DeauthConfirm";
  case DeauthIndicate_ID: return "DeauthIndicate";
  case DisassocConfirm_ID: return "DisassocConfirm";
  case DisassocIndicate_ID: return "DisassocIndicate";
  case GetConfirm_ID: return "GetConfirm";
  case JoinConfirm_ID: return "JoinConfirm";
  case PowermgtConfirm_ID: return "PowermgtConfirm";
  case ReassocConfirm_ID: return "ReassocConfirm";
  case ReassocIndicate_ID: return "ReassocIndicate";
  case ScanConfirm_ID: return "ScanConfirm";
  case SetConfirm_ID: return "SetConfirm";
  case StartConfirm_ID: return "StartConfirm";
  case ResyncConfirm_ID: return "ResyncConfirm";
  case SiteConfirm_ID: return "SiteConfirm";
  case SaveConfirm_ID: return "SaveConfirm";
  case RFtestConfirm_ID: return "RFtestConfirm";
  case AssocRequest_ID: return "AssocRequest";
  case AuthRequest_ID: return "AuthRequest";
  case DeauthRequest_ID: return "DeauthRequest";
  case DisassocRequest_ID: return "DisassocRequest";
  case GetRequest_ID: return "GetRequest";
  case JoinRequest_ID: return "JoinRequest";
  case PowermgtRequest_ID: return "PowermgtRequest";
  case ReassocRequest_ID: return "ReassocRequest";
  case ScanRequest_ID: return "ScanRequest";
  case SetRequest_ID: return "SetRequest";
  case StartRequest_ID: return "StartRequest";
  case MdRequest_ID: return "MdRequest";
  case ResyncRequest_ID: return "ResyncRequest";
  case SiteRequest_ID: return "SiteRequest";
  case SaveRequest_ID: return "SaveRequest";
  case RFtestRequest_ID: return "RFtestRequest";
  case MmConfirm_ID: return "MmConfirm";
  case MmIndicate_ID: return "MmIndicate";
  default:
    {
      static char buf[5];
      sprintf(buf,"<%02x>",sigid);
      return buf;
    }
  } /* switch (sigid) */
} /* sigid2str */
#endif //#if TRACE_NR_RECS > 0


#define STATE_ID_INVALID        1
#define STATE_ID_SCANNING       2
#define STATE_ID_STARTING_IBSS  3
#define STATE_ID_JOINING        4
#define STATE_ID_ASSOC          5
#define STATE_ID_AUTH           6
#define STATE_ID_JOINED_IBSS    7
#define STATE_ID_STARTED_IBSS   8
#define STATE_ID_JOINED_ESS     9

static struct _statetab { 
  State_fct_t fptr;
  char *name;
  int id;
} const sttab[] = {
  {state_invalid, "INVALID", STATE_ID_INVALID},
  {state_scanning, "SCANNING", STATE_ID_SCANNING},
  {state_starting_ibss, "STARTING_IBSS", STATE_ID_STARTING_IBSS},
  {state_joining, "JOINING", STATE_ID_JOINING},
  {state_assoc, "ASSOC", STATE_ID_ASSOC},
  {state_auth, "AUTH", STATE_ID_AUTH},
  {state_joined_ibss, "JOINED_IBSS", STATE_ID_JOINED_IBSS},
  {state_started_ibss, "STARTED_IBSS", STATE_ID_STARTED_IBSS},
  {state_joined_ess, "JOINED_ESS", STATE_ID_JOINED_ESS},
};

int const sttab_len = sizeof(sttab) / sizeof(struct _statetab);

/* == PROC state2str == */
static char *state2str(State_fct_t st, char *buf)
{
  struct _statetab const *tptr = sttab;
  int i = sttab_len;

  while (i) {
    if (tptr->fptr == st)
      return tptr->name;
    i--;
    tptr++;
  }

  sprintf(buf,"<%p>",st);
  return buf;
} /* state2str */


/* == PROC stateid2str == */
static char *stateid2str(int id, char *buf)
{
  struct _statetab const *tptr = sttab;
  int i = sttab_len;

  while (i) {
    if (tptr->id == id)
      return tptr->name;
    i--;
    tptr++;
  }

  sprintf(buf,"<%02x>",id);
  return buf;
} /* stateid2str */


/* == PROC state2id == */
static uint8 state2id(State_fct_t st)
{
  struct _statetab const *tptr = sttab;
  int i = sttab_len;

  while (i) {
    if (tptr->fptr == st)
      return tptr->id;
    i--;
    tptr++;
  }

  return 0xff;
} /* state2id */


/* == PROC newstate ==
   sets a new state if really new and debug it */
static void newstate(struct _wl24cb_t *cb, State_fct_t new_state)
{
  if (cb->state != new_state) {

#if TRACE_NR_RECS > 0
    if (cb->trace_mask & (1 << TRACE_NEW_STATE)) {
      uint8 buf[2];
      buf[0] = state2id(cb->state);
      buf[1] = state2id(new_state);

      trace_add(cb, TRACE_NEW_STATE, (uint8 *)buf, sizeof(buf));
    }
#endif

    if (cb->dbg_mask & DBG_STATES) {
      char buf1[32],buf2[32] ;
      printk(KERN_DEBUG "%s: state change %s -> %s\n",cb->name,
             state2str(cb->state,buf1), state2str(new_state,buf2));
    }
# ifdef WIRELESS_EXT
    cb->wstats.status = state2id(new_state);
# endif

    cb->state = new_state;
  }
}

/* == PROC was_card_removed == 
   returns TRUE if card was removed in the mean time */
static inline int was_card_removed(WL24Cb_t *cb)
{
  /* bit6 in BSS is reserved and reads permanently as zero */
  if (InB(cb->BaseAddr+NIC_BSS) == 0xff) {
#ifdef LOG_CARD_REMOVED
    printk(KERN_DEBUG "%s: %s card was removed\n", cb->name,
           __FUNCTION__);
#endif
    return 1;
  }
  return 0;
} /* was_card_removed */


/* == PROC disable_card_interrupt == 
  returns value != 0 if interrupts from card were enabled before */
static inline int disable_card_interrupt(WL24Cb_t *cb)
{
  uint8 old = InB(cb->BaseAddr + NIC_GCR);

  /* reset: interrupt indication bit from card, enable card interrupt bit */
  OutB(old & ~(GCR_ECINT|GCR_ENECINT), cb->BaseAddr + NIC_GCR);

#ifdef LOG_DISABLE_INTERRUPT
  printk(KERN_DEBUG "%s: %s: GCR old x%02x  new x%02x\n", cb->name, __FUNCTION__,
         old, InB(cb->BaseAddr+NIC_GCR));
#endif
  return old & GCR_ENECINT;
}


/* == PROC enable_card_interrupt == */
static inline void  enable_card_interrupt(WL24Cb_t *cb)
{
  OutB(InB(cb->BaseAddr + NIC_GCR) | GCR_ENECINT, cb->BaseAddr + NIC_GCR);
#ifdef LOG_ENABLE_INTERRUPT
  printk(KERN_DEBUG "%s: %s: GCR x%02x\n", cb->name, __FUNCTION__,
         InB(cb->BaseAddr+NIC_GCR));
#endif
}


/* == PROC stop_card ==
   stops the 80188 in the card 
   returns !=0 if card was running before */
static inline int stop_card(WL24Cb_t *cb)
{
  uint8 old = InB(cb->BaseAddr + NIC_GCR);

  OutB((old & ~(GCR_ECINT | GCR_INT2EC)) | GCR_ECWAIT, cb->BaseAddr + NIC_GCR);
  return !(old & GCR_ECWAIT);
}

/* == PROC start_card ==
   starts the 80188 in the card 
   returns !=0 if card was running before */
static inline int start_card(WL24Cb_t *cb)
{
  uint8 old = InB(cb->BaseAddr + NIC_GCR);

  /* reset: interrupt indication bit from card, enable card interrupt bit */
  OutB((old & ~(GCR_ECINT | GCR_INT2EC))|GCR_ECWAIT, cb->BaseAddr + NIC_GCR);
  return !(old & GCR_ECWAIT);
}


/* == PROC interrupt_to_card ==
   raise an interrupt to the card
   Found no place where an interrupt was sent to firmware in the old sw ? */
static inline void interrupt_to_card(WL24Cb_t *cb)
{
  /* should we busy wait until GCR_INT2EC is low ? */
  assert(!(InB(cb->BaseAddr+NIC_GCR) & GCR_INT2EC));

  /* old sw: & ~GCR_ECINT ??? */
  OutB(InB(cb->BaseAddr+NIC_GCR) | GCR_INT2EC,
       cb->BaseAddr + NIC_GCR);
}


/* == PROC printk_cardmem == */
void printk_cardmem(CardAddr_t addr, size_t sz, WL24Cb_t *cb)
{
  printk(KERN_DEBUG "%s cardmem @ %08x: ", cb->name, addr);

  OutB((addr&CARDADDR_MASK_PAGE)>>16,  cb->BaseAddr+NIC_BSS);
  OutB((addr&CARDADDR_MASK_OFFS)&0xff, cb->BaseAddr+NIC_LMAL);
  OutB((addr&CARDADDR_MASK_OFFS)>> 8,  cb->BaseAddr+NIC_LMAH);
  
  while (sz) {
    printk("%02x ",InB(cb->BaseAddr+NIC_IODPA));
    sz--;
  }
  printk("\n");
} 


/* == PROC printk_cardmem_words == */
void printk_cardmem_words(CardAddr_t addr, size_t sz, WL24Cb_t *cb)
{
  uint8 lower, upper;
  printk(KERN_DEBUG "%s cardmem @ %08x: ", cb->name, addr);

  OutB((addr&CARDADDR_MASK_PAGE)>>16,  cb->BaseAddr+NIC_BSS);
  OutB((addr&CARDADDR_MASK_OFFS)&0xff, cb->BaseAddr+NIC_LMAL);
  OutB((addr&CARDADDR_MASK_OFFS)>> 8,  cb->BaseAddr+NIC_LMAH);
  
  while (sz) {
    lower = InB(cb->BaseAddr+NIC_IODPA); /* read lower byte */
    upper = InB(cb->BaseAddr+NIC_IODPA); /* read upper byte */
    printk("%02x%02x ",upper,lower);
    sz--;
  }
  printk("\n");
} 


/* == PROC copy_from_card ==
   copy sz many bytes from card address into host address
   if sz == 0 we only switch the bank address in NIC_BSS
   Set slow to TRUE if flash is read. */
static void copy_from_card(void *dest, CardAddr_t src, 
                           size_t size, int slow, WL24Cb_t *cb)
{
  size_t sz = size;
  uint8 *db = dest;
  int page = (src&CARDADDR_MASK_PAGE)>>16;
  unsigned int offset = src&CARDADDR_MASK_OFFS;

#ifdef LOG_COPY_PROCS
  printk(KERN_DEBUG "%s %s(%p,%x,%x,%d,..)\n",
         cb->name, __FUNCTION__, dest, src, size, slow);
#endif

  OutB(page, cb->BaseAddr+NIC_BSS);
  OutB(offset & 0xff, cb->BaseAddr+NIC_LMAL);
  OutB(offset >> 8,   cb->BaseAddr+NIC_LMAH);
  
  while (sz--) {
    if (slow)
      udelay(10);
    *db++ = InB(cb->BaseAddr + NIC_IODPA); /* autodecrement of LMA[HL] address */
  }

#ifdef LOG_COPY_PROCS
  printk_cardmem(src,MIN(size,8),cb);
#endif
} 


/* == PROC copy_to_card ==
   copies sz many byte from src (host address space) to 
   dest (card address space). Protect outside against interrupt ! */
static inline void copy_to_card(CardAddr_t dest, void *src, 
                                int sz, WL24Cb_t *cb)
{
#ifdef LOG_COPY_PROCS
  printk(KERN_DEBUG "%s %s(%x,%p,%x,..)\n",
         cb->name, __FUNCTION__, dest, src, sz);
#endif

  OutB((dest&CARDADDR_MASK_PAGE)>>16,  cb->BaseAddr+NIC_BSS);
  OutB((dest&CARDADDR_MASK_OFFS)&0xff, cb->BaseAddr+NIC_LMAL);
  OutB((dest&CARDADDR_MASK_OFFS)>>8,   cb->BaseAddr+NIC_LMAH);

  /* rep out to Port A */
  OutSB(cb->BaseAddr + NIC_IODPA, src, sz);

#ifdef LOG_COPY_PROCS
  printk_cardmem(dest, MIN(sz,8), cb);
#endif
}

/* == PROC copy_words_to_card ==
   copies sz many words (uint16) from src (host address space) to 
   dest (card address space). Protect outside against interrupt ! 
   Obey endians: card has little endian in byte-order */
static inline void copy_words_to_card(CardAddr_t dest, uint16 const *src, 
                                      size_t size, WL24Cb_t *cb)
{
  size_t sz = size;
#ifdef LOG_COPY_PROCS
  printk(KERN_DEBUG "%s %s(%x, %p, %x,..)\n",
         cb->name, __FUNCTION__, dest, src, sz);
#endif

  OutB((dest&CARDADDR_MASK_PAGE)>>16,  cb->BaseAddr+NIC_BSS);
  OutB((dest&CARDADDR_MASK_OFFS)&0xff, cb->BaseAddr+NIC_LMAL);
  OutB((dest&CARDADDR_MASK_OFFS)>>8,   cb->BaseAddr+NIC_LMAH);

  while (sz--) {
    OutB(*src & 0xff, cb->BaseAddr + NIC_IODPA);
    OutB(*src >> 8,   cb->BaseAddr + NIC_IODPA);
    src++;
  }
#ifdef LOG_COPY_PROCS
  printk_cardmem_words(dest, MIN(size,8),cb);
#endif
}

/* == PROC copy_words_from_card ==
   copies sz many words (uint16) from src (card address space) to 
   dest (host address space). Protect outside against interrupt ! 
   Obey endians: card has little endian in byte-order */
static inline void copy_words_from_card(uint16 *dest, CardAddr_t src,
                                        size_t sz, WL24Cb_t *cb)
{
  uint8 lower;
  int i;
#ifdef LOG_COPY_PROCS
  printk(KERN_DEBUG "%s %s(%p,%x,%x,..)\n",
         cb->name, __FUNCTION__, dest, src, sz);
#endif

  OutB((src&CARDADDR_MASK_PAGE)>>16,  cb->BaseAddr+NIC_BSS);
  OutB((src&CARDADDR_MASK_OFFS)&0xff, cb->BaseAddr+NIC_LMAL);
  OutB((src&CARDADDR_MASK_OFFS)>>8,   cb->BaseAddr+NIC_LMAH);

  i = 0;
  while (i++ < sz) {
    /* make it in two statements, because we must read the lower part first
       (autoincrement of address) and I dunno the order of execution
       of the expression InB(...) | InB(...)) */
    lower = InB(cb->BaseAddr + NIC_IODPA);
    *dest++ = lower | (InB(cb->BaseAddr + NIC_IODPA)<< 8);
  }

#ifdef LOG_COPY_PROCS
  printk_cardmem_words(src, MIN(sz,8),cb);
#endif
}


/* == PROC init_esbq_txbuf ==
 read the buffer pointer for ESBQ and TxBuf and build txbuf chain */
static void init_esbq_txbuf(WL24Cb_t *cb)
{
  Card_BufInfo_t bufinfo;
  Card_Word_t txbuf, next_txbuf; 
  copy_words_from_card((uint16 *)&bufinfo, WL_SELFTEST_ADDR,
                       sizeof(Card_BufInfo_t)/sizeof(Card_Word_t), cb);

#ifdef LOG_INIT_ESBQ_TXBUF
  printk(KERN_DEBUG "%s: %s: selftest x%04x ESBQReqStartAddr x%04x ESBQReqSize x%04x\n",
         cb->name, __FUNCTION__, bufinfo.selftest, bufinfo.ESBQReqStartAddr, bufinfo.ESBQReqSize);
  printk(KERN_DEBUG "%s: %s: ESBQCfmStartAddr x%04x ESBQCfmSize x%04x\n",
         cb->name, __FUNCTION__, bufinfo.ESBQCfmStartAddr, bufinfo.ESBQCfmSize);
  printk(KERN_DEBUG "%s: %s: TxBufHead x%04x TxBufSize x%04x\n",
         cb->name, __FUNCTION__, bufinfo.TxBufHead, bufinfo.TxBufSize);
#endif

  cb->ESBQReqHead = cb->ESBQReqTail = cb->ESBQReqStart = 
    bufinfo.ESBQReqStartAddr;
  cb->ESBQReqEnd = bufinfo.ESBQReqStartAddr + bufinfo.ESBQReqSize;
  cb->ESBQCfm = cb->ESBQCfmStart = bufinfo.ESBQCfmStartAddr;
  cb->ESBQCfmEnd = bufinfo.ESBQCfmStartAddr + bufinfo.ESBQCfmSize;

  cb->FreeTxBufStart = bufinfo.TxBufHead;
  cb->FreeTxBufEnd   = bufinfo.TxBufHead + bufinfo.TxBufSize;

  cb->FreeTxBufList = bufinfo.TxBufHead;

  cb->FreeTxBufLen = 1;
  txbuf = cb->FreeTxBufList;
  next_txbuf = txbuf + sizeof(Card_TxBuf_t); /* start of next txbuf */
  while ((next_txbuf - bufinfo.TxBufHead) < bufinfo.TxBufSize) {
    /* next_txbuf is still inside the TxBuf area */
    cb->FreeTxBufLen++;
    /* write next_txbuf to next field of Card_TxBuf_t @ address txbuf */
    copy_words_to_card(txbuf+offsetof(Card_TxBuf_t,next),&next_txbuf,1,cb);
    txbuf = next_txbuf;
    next_txbuf += sizeof(Card_TxBuf_t);
  }
  /* finish linked list with NULL pointer */
  next_txbuf = 0;
  copy_words_to_card(txbuf+offsetof(Card_TxBuf_t,next),&next_txbuf,1,cb);
  cb->FreeTxBufTail = txbuf; /* remember last buffer in linked list */

  cb->txbuf_len_list_len = cb->FreeTxBufLen;
  if (cb->txbuf_len_list == NULL)
    /* might be allocated from last run */
    cb->txbuf_len_list = kmalloc(cb->FreeTxBufLen * sizeof(uint16), GFP_KERNEL);
  memset(cb->txbuf_len_list,0, cb->FreeTxBufLen * sizeof(uint16));

#ifdef LOG_INIT_ESBQ_TXBUF
  printk(KERN_DEBUG "%s %s: FreeTxBufList x%04x FreeTxBufTail x%04x FreeTxBufLen x%x\n",
         cb->name, __FUNCTION__, cb->FreeTxBufList, cb->FreeTxBufTail,
         cb->FreeTxBufLen);
#endif

#ifdef CHECK_ALLOC_TXBUF
  {
    int i;
    if (cb->dbg_txbuf == NULL)
      cb->dbg_txbuf = kmalloc(cb->FreeTxBufLen * sizeof(DbgTxBuf_t), GFP_KERNEL);
    assert(cb->dbg_txbuf);
    for(i=0; i < cb->FreeTxBufLen; i++)
      cb->dbg_txbuf[i].used = 0;
  }
  cb->dbg_chk_txbuf_print = 10; /* we want to see that many warnings in case of inconsistent txbuffers */
#endif
} /* init_esbq_txbuf */

/* == PROC read_flash_params ==
   reads card name, firmware date, MAC address, 
   firmware version and freq domain from flash */
static void read_flash_params(WL24Cb_t *cb)
{

  copy_from_card(cb->MacAddress, WL_FLASH_MAC, SZ_MAC_ADDR, COPY_SLOW, cb);
  copy_from_card(&cb->FreqDomain, WL_FREQ_DOMAIN, 1, COPY_SLOW, cb);

  cb->frdesc = getFreqDomainDescr(cb->FreqDomain);

  if (cb->Channel == 0 || cb->Channel > 32 || (!(cb->frdesc->channel_map & (1L<<(cb->Channel-1))))) {
    printk(KERN_INFO "%s: %s: Channel %d not allowed in domain %s, using %d instead\n",
           cb->name, __FUNCTION__, cb->Channel, cb->frdesc->name, cb->frdesc->default_ch);
    cb->Channel = cb->frdesc->default_ch;
  }

#ifdef LOG_FREQDOMAIN
  printk(KERN_DEBUG "%s: %s: freq. domain %s: channel_map x%08x\n",
         cb->name, __FUNCTION__, cb->frdesc->name, cb->frdesc->channel_map);

#endif

  { /* firmware is a little endian 16 bit word, but we don't have
       a copy_word_from_card with slow access (for flash ??)*/
    copy_from_card(&cb->FWversion, WL_FW_VERSION, 2, COPY_SLOW, cb);
  }
}

/* == PROC read_ram_params ==
   reads card name, firmware date from ram (after selftest) */
static void read_ram_params(WL24Cb_t *cb)
{
  int i;

  /* get card name and firmware date */
  copy_from_card(cb->CardName, WL_CARDNAME, sizeof(cb->CardName)-1,
                 COPY_FAST, cb);
  /* insert \0 */
  for(i=0; i < sizeof(cb->CardName)-1; i++)
    if (cb->CardName[i] < ' ')
      break;
  cb->CardName[i] = '\0';

  copy_from_card(cb->FirmwareDate, WL_FIRMWARE_DATE, sizeof(cb->FirmwareDate)-1,
                 COPY_FAST, cb);
  /* insert \0 */
  for(i=0; i < sizeof(cb->FirmwareDate)-1; i++)
    if (cb->FirmwareDate[i] < ' ')
      break;
  cb->FirmwareDate[i] = '\0';
} /* read_ram_params */


/* == PROC init_scanlist == */
static void init_scanlist(WL24Cb_t *cb)
{
  int i;

  cb->currBSS = -1;
  cb->scan_runs = 0;

  memset(cb->BSSset,0,sizeof(cb->BSSset));

  for(i=0;i<NR_BSS_DESCRIPTIONS;i++) {
    cb->BSSset[i].valid = 0;
    memset(cb->BSSset[i].SSID,0,sizeof(cb->BSSset[i].SSID));
  }
}

/* == PROC restart_card ==
   resets the card and starts it.
   returns 0 if reset failed, 1 otherwise */
int restart_card(WL24Cb_t *cb)
{
  uint8 cTmp;
  int   i;
    
  netif_carrier_off(cb->netdev); /* disable running netdevice watchdog */
  netif_stop_queue(cb->netdev); /* this proc might be called from 
                                   somewhere in state_* */

  printk(KERN_DEBUG "%s: restart_card, base x%x\n",
         cb->name, cb->BaseAddr);

  /* reset */
  OutB_P(GCR_CORESET, cb->BaseAddr + NIC_GCR);
  udelay(50);

  /* set self test address to zero */
  cTmp = 0;
  copy_to_card(WL_SELFTEST_ADDR, &cTmp, 1, cb); 

  /* Start up */
  OutB_P(0, cb->BaseAddr + NIC_GCR);
    
  /* let the firmware start up */
  udelay(1000);

  /* Polling Self_Test_Status */    
  for (i = 0; i < 100; i++) {
    copy_from_card(&cTmp, WL_SELFTEST_ADDR, 1, COPY_SLOW, cb);
#ifdef LOG_RESTART_CARD
    printk(KERN_DEBUG "%s: restart_card: read x%02x @ x%04x\n",
           cb->name, cTmp, WL_SELFTEST_ADDR);
#endif
    if (cTmp == 'W') {
      /* firmware has completed all tests successfully */

      read_flash_params(cb); // MAC addr, fw version, freq domain

      /* is the transparent mode available ? */
      cb->cardmode = ((cb->FWversion[0] == 2) && (cb->FWversion[1] >= 6)) ? 'H' : 'A';

      printk(KERN_DEBUG "%s:using card mode %c (%d)\n", cb->name,
             cb->cardmode, cb->cardmode);
      cTmp = cb->cardmode; /* 'A' resp. 'H' */
      copy_to_card(WL_SELFTEST_ADDR, &cTmp, 1, cb); 
      break;
    }
    udelay(500);
  }

  if (i >= 100) {
    printk(KERN_WARNING "%s: cannot reset card\n", cb->name);
    return FALSE;
  }

  init_esbq_txbuf(cb); /* get the ESBQ / FreeTxBuf pointers */
  init_scanlist(cb); /* init. cb-> vars for initial scan */
      
  /* copy the MAC address into the net_device struct */
  memcpy(cb->netdev->dev_addr,cb->MacAddress,sizeof(cb->netdev->dev_addr));

  read_ram_params(cb); 
  
  if (cb->dbg_mask & DBG_INITIALIZATION) {
    printk(KERN_DEBUG "%s: card %s\n", cb->name, cb->CardName);
    printk(KERN_DEBUG "%s: MAC %02x:%02x:%02x:%02x:%02x:%02x freq domain %s (x%02x) "
           "firmware version %d.%d (date %s)\n",cb->name,
           cb->MacAddress[0],cb->MacAddress[1],cb->MacAddress[2],
           cb->MacAddress[3],cb->MacAddress[4],cb->MacAddress[5],
           cb->frdesc->name, cb->FreqDomain,
           cb->FWversion[0],cb->FWversion[1],
           cb->FirmwareDate);
  }

  /* init some state info */

  cb->mdcfm_failure = 0; /* the failure counter */

  /* invalidate rx fragment cache */
  for(i=0; i < NR_RX_FRAG_CACHES; i++)
    cb->rx_cache[i].in_use = 0;

  /* init. state machine and send first request to firmware */
  newstate(cb,state_scanning);
  
  /* acknowledge Interrupt and enable them */
  OutB(GCR_ECINT | GCR_ENECINT, cb->BaseAddr + NIC_GCR);

  /* try to find all infrastructure BSS and IBSS for a properly filled
     BSSset[] table. We match the correct BSS type later. */
  ScanReq(cb, SCAN_MIN_CHANNEL_TIME, SCAN_FIRST_RUN_MAX_CHANNEL_TIME,
          BSSType_AnyBSS, ScanType_Active);
  
  /* reset statistics */
  memset(&cb->stats,0,sizeof(cb->stats));
#ifdef WIRELESS_EXT
  memset(&cb->wstats,0,sizeof(cb->wstats));
#endif

  cb->was_restarted = 1;
  return TRUE;

} /* end of restart_card */


/* == PROC alloc_txbuf ==
   get a linked list of free tx buffer.
   returns the address of the first chain elem or NULL if failed. */
Card_Word_t alloc_txbuf(WL24Cb_t *cb, size_t sz)
{
  Card_Word_t retval = 0, prev, next;
  size_t len = sz;
  uint16 count = 0;

  if (was_card_removed(cb)) {
    return 0;
  }

  if (sz <= (cb->FreeTxBufLen * CARD_TXBUF_DATA_SIZE)) {

    retval = next = cb->FreeTxBufList;

    do {

#ifdef CHECK_ALLOC_TXBUF
      dbg_txbuf_mark(cb,next,1,retval); /* mark the buffer as used, no parent */
#endif

      prev = next;

      copy_words_from_card(&next, prev+offsetof(Card_TxBuf_t,next), 1, cb);
      sz -= MIN(sz,CARD_TXBUF_DATA_SIZE);
      count++;

    } while (sz > 0 && next != 0);

    /* cb->FreeTxBufLen showed the wrong number or the free list got
       incosistent */
    assert(sz == 0);

    /* cross check length and number of buffers */
    assert(count == ((len+CARD_TXBUF_DATA_SIZE-1)/CARD_TXBUF_DATA_SIZE));

    /* break the free list */
    copy_words_to_card(prev, &cwZero, 1, cb);
    cb->FreeTxBufList = next;
    cb->FreeTxBufLen -= count;
  }

#ifdef LOG_ALLOC_TXBUF
  printk(KERN_DEBUG "%s: %s(%x) -> %x\n", cb->name, __FUNCTION__, len, retval);
  printk(KERN_DEBUG "%s: FreeTxBuf list %x len %x tail %x\n", cb->name,
         cb->FreeTxBufList, cb->FreeTxBufLen, cb->FreeTxBufTail);
#endif

#ifdef CHECK_ALLOC_TXBUF
  /* if we have exhausted the txbuffer, list the time and the signals 
     of buffers allocated long ago */
#define TIME_THRESHOLD 100

  if (retval == 0) {
    int i;
#if 0
    printk(KERN_DEBUG "%s: %s need %d buffer, have only %d\n", cb->name,
           __FUNCTION__,
           (len+CARD_TXBUF_DATA_SIZE-1)/CARD_TXBUF_DATA_SIZE, cb->FreeTxBufLen);
#endif
    for(i=0; i < (cb->FreeTxBufEnd - cb->FreeTxBufStart) / 
          sizeof(Card_TxBuf_t); i++) {
      Card_Word_t addr = cb->FreeTxBufStart + i*sizeof(Card_TxBuf_t);
      if (cb->dbg_txbuf[i].used && 
          (cb->dbg_txbuf[i].jiffies < (jiffies - TIME_THRESHOLD)))
        printk(KERN_DEBUG "%s: %s buf @ x%x long time since alloc %lu,"
               " parent x%x, sigid x%x\n", 
               cb->name, __FUNCTION__, addr, jiffies - cb->dbg_txbuf[i].jiffies,
               cb->dbg_txbuf[i].parent, cb->dbg_txbuf[i].sigid);
    }
  }
#endif

  if (retval != 0) {
    /* store the data len in cb->txbuf_len_list[] for statistics */
    int nr = (retval - cb->FreeTxBufStart) / sizeof(Card_TxBuf_t);
    if (nr >= 0 && nr < cb->txbuf_len_list_len)
      cb->txbuf_len_list[nr] = len;
  }

  return retval;
} /* end of alloc_txbuf */


/* == PROC free_txbuf ==
   free an allocated tx buffer */
void free_txbuf(WL24Cb_t *cb, Card_Word_t buf)
{
  assert(buf != 0);
  if (buf == 0)
    return;

  if (was_card_removed(cb)) {
    return;
  }

#ifdef LOG_FREE_TXBUF
  printk(KERN_DEBUG "%s: %s(%x)\n", cb->name, __FUNCTION__, buf);
#endif

  if (cb->FreeTxBufList == 0) {
    cb->FreeTxBufList = buf;
    assert(cb->FreeTxBufLen == 0);
  } else {
    copy_words_to_card(cb->FreeTxBufTail, &buf, 1,cb);
  }

  /* look for the tail of the linked list at buf */

#ifdef CHECK_ALLOC_TXBUF
  /* mark the buffer as unused */
  if (!dbg_txbuf_mark(cb,buf,0,-1)) {

    /* something is wrong with the buffer */
    uint16 addr = 0, next;
    /* restore next field in tail */
    copy_words_to_card(cb->FreeTxBufTail, &addr, 1,cb);
    /* dump buffers in free list */
    printk(KERN_WARNING "%s: %s FreeTxBuf list x%x len x%x tail x%x, dumping the chain:\n", cb->name,
           __FUNCTION__, cb->FreeTxBufList, cb->FreeTxBufLen, cb->FreeTxBufTail);
    addr = cb->FreeTxBufList;
    while (addr != 0) {
      if (!check_buf_addr(cb, "", "", addr))
        break;
      copy_words_from_card(&next, addr, 1,cb);
      printk(KERN_WARNING "%s: buf x%x next x%x\n", cb->name, addr, next);
      addr = next;
    }
    return;
  }
#endif

  do {

    cb->FreeTxBufTail = buf;
    cb->FreeTxBufLen++;
    copy_words_from_card(&buf,buf+offsetof(Card_TxBuf_t,next), 1, cb);

#ifdef CHECK_ALLOC_TXBUF
    if (buf != 0)
      dbg_txbuf_mark(cb,buf,0,-1); /* mark the buffer as unused */
#endif

  } while (buf != 0);

#ifdef LOG_FREE_TXBUF
  printk(KERN_DEBUG "%s: %s: leaving with FreeTxBuf list x%x len x%x tail x%x\n", cb->name,
         __FUNCTION__, cb->FreeTxBufList, cb->FreeTxBufLen, cb->FreeTxBufTail);
#endif
} /* end of free_txbuf */


#define ESBQ_OWNED_BY_DRV 0x8000
/* if this bit is set in owner below, the ESBQ is owned by the driver,
   i.e. a request, which was processed by the card or a new confirm
   to be processed by the driver */
typedef struct {
  Card_Word_t buf; /* a linked list of tx/rx buffer 
                      containing the request/confirm */
  Card_Word_t owner; /* bit 15 is set if the driver owns the esbq */
} PACKED Card_ESBQ_t;

/* the size of an ESBQ struct in card words */
#define SZ_ESBQ_W (sizeof(Card_ESBQ_t)/sizeof(Card_Word_t))


/* each buffer in the chain at MdInd.Data starts with this struct. */
typedef struct {
  uint16  RxNextBlock;      /* ??? */
  uint16  RxNextFrameBlock; /* points to next buffer in chain */
  uint8   RxBlockCtrl;      /* ??? */
} PACKED RxFrameLinkHeader_t;


/* PROC read_rxbuf ==
   read data from a rxbuf into data area in host memory 
   the last param "skip" says how many bytes we shall skip
   in the first segment */
void read_rxbuf(WL24Cb_t *cb, void *dest_addr, uint16 len, Card_Word_t rxbuf,
                uint16 skip)
{
  uint16 nr_to_copy;
  uint8 *dst = dest_addr;

#ifdef LOG_READ_RXBUF
  printk(KERN_DEBUG "%s %s:  len x%x rxbuf x%x skip x%x\n", 
         cb->name, __FUNCTION__, len, rxbuf, skip);
#endif

  do {

    nr_to_copy = MIN(len, CARD_RXBUF_SIZE-skip);
    copy_from_card(dst, rxbuf+skip, nr_to_copy, COPY_FAST, cb);
    dst += nr_to_copy;
    len -= nr_to_copy;

    /* get pointer to next buf in rxbuf chain */
    copy_words_from_card(&rxbuf,
                         rxbuf+offsetof(RxFrameLinkHeader_t,RxNextFrameBlock),
                         1, cb);

    /* in all but the first buffer we only skip the frame link header */
    skip = sizeof(RxFrameLinkHeader_t);

  } while (len > 0);
} /* end of read_rxbuf */

/* == PROC request_to_card ==
   Sends a request to card. 
   The request is stored in ReqSz many bytes at ReqBuf in host memory. */
int request_to_card(WL24Cb_t *cb, void *ReqBuf, size_t ReqSz)
{
  Card_ESBQ_t req;
  Card_Word_t txbuf;

#if TRACE_NR_RECS > 0
  if (cb->trace_mask & (1 << TRACE_MSG_SENT)) {
    trace_add(cb, TRACE_MSG_SENT, (uint8 *)ReqBuf+2, TRACE_DATA_LEN);
  }
#endif

  if (ReqSz > CARD_TXBUF_DATA_SIZE) {
    printk(KERN_WARNING "%s: request size (%d) larger than txbuf size (%d)\n",
           cb->name, ReqSz, CARD_TXBUF_DATA_SIZE);
    return FALSE;
  }

  /* NextBlock must be zero */
  assert(*((uint16 *)ReqBuf) ==  0);

  txbuf = alloc_txbuf(cb,ReqSz);
  if (!txbuf) {
    
#if 0 // this is rather normal under heavy traffic !
    printk(KERN_WARNING "%s: cannot alloc txbuf of %d byte\n",
           cb->name, ReqSz);
    printk(KERN_DEBUG "%s: FreeTxBuf: List x%x Tail x%x Len x%x\n",
           cb->name, cb->FreeTxBufList, cb->FreeTxBufTail, cb->FreeTxBufLen);
#endif
    return FALSE;
  }

#ifdef CHECK_ALLOC_TXBUF
  /* set the sigid of the parent buffer */
  dbg_txbuf_set_sigid(cb, txbuf, *((uint8 *)ReqBuf+2));
#endif
  copy_to_card(txbuf, ReqBuf, ReqSz, cb);

  copy_words_from_card((uint16 *)&req, cb->ESBQReqHead, SZ_ESBQ_W, cb);
  if (req.owner & ESBQ_OWNED_BY_DRV) {
    req.buf = txbuf;
    /* original sw: req.owner = 0 ??? */
    req.owner = 0; /* firmware becomes owner */
    /* SUTRO firmware seems to poll on the owner bit */
    copy_words_to_card(cb->ESBQReqHead, (uint16 const *)&req, SZ_ESBQ_W, cb);

    cb->ESBQReqHead += sizeof(Card_ESBQ_t);
    if (cb->ESBQReqHead >= cb->ESBQReqEnd)
      cb->ESBQReqHead = cb->ESBQReqStart;

    return TRUE;

  } else {
    free_txbuf(cb,txbuf);
    printk(KERN_WARNING "%s: cannot alloc ESBQ buffer\n",cb->name);
    return FALSE;
  }
} /* request_to_card */


/* == PROC free_requests ==
   free all processed ESBQ buffers and their tx buffer */
void free_requests(WL24Cb_t *cb)
{
  Card_ESBQ_t req;
#ifdef LOG_FREE_REQUESTS
  printk(KERN_DEBUG "%s: %s: ESBQ head %x tail %x\n",
         cb->name, __FUNCTION__, cb->ESBQReqHead, cb->ESBQReqTail);
#endif

  while (cb->ESBQReqTail != cb->ESBQReqHead) {
    copy_words_from_card((uint16 *)&req, cb->ESBQReqTail, SZ_ESBQ_W, cb);
#ifdef LOG_FREE_REQUESTS
    printk(KERN_DEBUG "%s: %s: ESBQ @ %x: owner %x buf %x\n",
           cb->name, __FUNCTION__, cb->ESBQReqTail, req.owner, req.buf);
#endif

    if (req.owner & ESBQ_OWNED_BY_DRV) {
      /* got it back from firmware */
      free_txbuf(cb,req.buf);
      cb->ESBQReqTail += sizeof(Card_ESBQ_t);
      if (cb->ESBQReqTail >= cb->ESBQReqEnd)
        cb->ESBQReqTail = cb->ESBQReqStart;
    } else
      break;
  }
}

/* == PROC confirm_avail ==
   Check if an unprocessed ESBQ Confirm is available.
   If yes, return address of associated buffer. If no, return 0.
   It's free'd  by calling free_confirm */
Card_Word_t confirm_avail(WL24Cb_t *cb)
{
  Card_ESBQ_t cfm;
  
  copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);
  if (cfm.owner & ESBQ_OWNED_BY_DRV) {
    /* new confirm from card */
    return cfm.buf;
  } else
    return 0;
}

/* WL_ESBQConfirm */

/* == PROC free_confirm ==
   free an ESBQ confirm, which was found available before
   (now the card's firmware can reuse the buffer associated) */
void free_confirm(WL24Cb_t *cb)
{
  
  Card_ESBQ_t cfm;
  
  copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);
  /* give esbq back to firmware */
  cfm.owner &= 0xff; /* original sw: reset bit15-8 ??? */
  copy_words_to_card(cb->ESBQCfm, (uint16 const*)&cfm, SZ_ESBQ_W, cb);
}


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Routing;
  uint16  Data; /* starts with TxHeader_t below */
  uint16  Size;
  uint8 Priority;
  uint8 ServiceClass;
  uint8 DAddress[6];
  uint8 SAddress[6];
} PACKED MdReq_t;


typedef struct {
  uint16  XmitCount;
  uint8   SYNC[16];
  uint16  SFD;
  uint8   SIGNAL;
  uint8   SERVICE;
  uint16  LENGTH;
  uint16  CRC16;
  uint16  FrameControl;
  uint16  DurationID;
  uint8   Address1[6];
  uint8   Address2[6];
  uint8   Address3[6];
  uint16  SequenceControl;
  //uint8   Address4[6];
} PACKED TxHeader_t;

/* we must add this to the payload to get the value for LENGTH above
   (resp. MdReq_t.Size)
   jal: guess: +4 for the 32 bit FCS at the end of transmission 
   (see [1], pg. 44) */
#define TXHEADER_HEADER_SIZE \
   (sizeof(TxHeader_t)-offsetof(TxHeader_t,FrameControl)+4)

/* == PROC TxDataReq ==
   transmit an Ethernet raw frame:
    src[0..5] is the destination MAC addr
    src[6..11] is the source MAC addr
    - we allocate a struct t_MdReq and a tx_buffer (maybe a chain of buffers !)
    - for LLCType_WaveLan we either use SNAP encapsulation if src[12,13] is
      a protocol id. Or we skip the length in src[12,13]
    - for LLCType_IEEE802_11 we leave the MAC addresses in the payload
*/
int TxDataReq(WL24Cb_t *cb, void *vsrc, uint16 len, LLCType_t llctype)
{
  uint16 dbg_len = len; /* for debugging output */
  uint8 *src = vsrc;
  Card_Word_t dbuf; /* here go the data from src with a TxHeader_t in front */
  MdReq_t Req;

  int ThisLen, RestLen;
  uint16 ptr;
  uint8 *pBuffer;

  /* copy the data to the temp buffer.  assure enough space at beginning 
     for header conversion. */

  wl24fill(&cb->databuffer, vsrc, len, 32);

  /* convert to 802.11 */

  wl24pack(&cb->databuffer, llctype,
           cb->BSSset[cb->currBSS].CapabilityInfo & 1,
           cb->BSSset[cb->currBSS].BSSID);

  /* encrypt ? */

  if (cb->wepstate.encrypt)
    wl24encrypt(&cb->databuffer, &cb->wepstate);

  /* we might alloc too much, 'cause the len input parameter includes the dest/src
     MAC address which are removed from the payload for Wavelan.
     Otherwise we might decide to add 6 byte SNAP encapsulation there.
     For IEEE802_11 the length is correct ! */
  dbuf = alloc_txbuf(cb, cb->databuffer.length + sizeof(TxHeader_t));
  if (dbuf == 0)
    return FALSE;

#ifdef CHECK_ALLOC_TXBUF
  /* set the sigid of the parent buffer 
     use dummy sigid aa for a txdata data chain */
  dbg_txbuf_set_sigid(cb, dbuf, 0xAA);
#endif

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = MdRequest_ID;
  Req.Data = cpu_to_le16(dbuf);
  /* copy MAC destination & source address from start of passed data */
  memcpy(Req.DAddress, src, sizeof(Req.DAddress)+sizeof(Req.SAddress));

#ifdef LOG_TXDATAREQ_INCOMING
  printk(KERN_DEBUG "%s: %s: in ",cb->name, __FUNCTION__);
  dumpk(src,MIN(len,32));
  printk("\n");
#endif

  /* copy in frame, starting at FrameControl field in 802.11
     header.  Note the 802.11 header will be overwritten by the card
     in case we do not work in transparent mode */ 

  RestLen = cb->databuffer.length;
  pBuffer = cb->databuffer.buffer + cb->databuffer.offset;
  ThisLen = min(RestLen, 204 + 24);
  copy_to_card(dbuf + 28, pBuffer, ThisLen, cb);
  pBuffer += ThisLen; RestLen -= ThisLen;
  copy_words_from_card(&ptr, dbuf, 1, cb);
  while (RestLen)
    {
      ThisLen = min(RestLen, 254);
      copy_to_card(ptr + 2, pBuffer, ThisLen, cb);
      pBuffer += ThisLen; RestLen -= ThisLen;
      copy_words_from_card(&ptr, ptr, 1, cb);
    }

  /* Tx size is 802.11 frame's length, including FCS */

  Req.Size = cb->databuffer.length + 4;

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_TXDATA_REQ)) {
    printk("%s: TxDataReq Dest %02x:%02x:%02x:%02x:%02x:%02x "
           "Src %02x:%02x:%02x:%02x:%02x:%02x len %d\n",
           cb->name,
           Req.DAddress[0],Req.DAddress[1],Req.DAddress[2],
           Req.DAddress[3],Req.DAddress[4],Req.DAddress[5],
           Req.SAddress[0],Req.SAddress[1],Req.SAddress[2],
           Req.SAddress[3],Req.SAddress[4],Req.SAddress[5],
           dbg_len);
    if (cb->msg_to_dbg_mask & DBG_TXDATA_REQ_DATA) {
      uint8 buf[32];
      int i;
      copy_from_card(buf, le16_to_cpu(Req.Data)+
                     offsetof(Card_TxBuf_t,data)+sizeof(TxHeader_t),
                     sizeof(buf),
                     COPY_FAST, cb);
      printk(KERN_DEBUG "%s: Tx Data ", cb->name);
      for(i=0; i < sizeof(buf); i++) printk("%02x",buf[i]);
      printk("\n");
    }
  }
  /* send the request */
  if (!request_to_card(cb,&Req,sizeof(Req))) {
    /* free appended tx data buffer */
    free_txbuf(cb, le16_to_cpu(Req.Data));
    return FALSE;
  } else
    return TRUE;

} /* end of TxDataReq */


/* == PROC wl24n_tx == */
int wl24n_tx (struct sk_buff *skb, struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;
  int int_enabled, is_sent;

  if (skb == NULL || skb->len <= 0)
    return 0;

  /* jal: do we need a spinlock here ??? */

  /* mask interrupt from card to occur during TxDataReq() */
  int_enabled = disable_card_interrupt(cb);

  is_sent = TxDataReq(cb, skb->data, skb->len, cb->llctype);

  if (int_enabled)
    enable_card_interrupt(cb);

  if (is_sent) {
    dev_kfree_skb(skb);
    dev->trans_start = jiffies;
    return 0;
  } else {
    netif_stop_queue(dev);
    return 1;   /* Try next time after MdCfm was received in ISR */
  }
} /* end of wl24n_tx */

/* == PROC wl24n_card_netif_stop ==
   stops the netif of the driver */
void wl24n_card_netif_stop(void *priv)
{
  WL24Cb_t *cb = priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_card_netif_stop\n",cb->name);

  netif_device_detach(cb->netdev);

} /* wl24n_card_netif_stop */


/* == PROC wl24n_card_reset == */
int wl24n_card_reset(void *priv)
{
  WL24Cb_t *cb = priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_card_reset\n",cb->name);

  disable_card_interrupt(cb);
  if (!(cb->card_started=restart_card(cb))) {
    printk(KERN_DEBUG "%s: failed to reset card\n",cb->name);
    return 0;
  }
  return 1;
} /* wl24n_card_reset */


/* == PROC wl24n_card_stop ==
   called to release alloced memory etc. */
void wl24n_card_stop(void *priv)
{
  WL24Cb_t *cb = priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_card_stop\n",cb->name);

  // not needed, because wl24n_close did it.
  //! disable_card_interrupt(cb->dev)
  //! netif_device_detach(cb->dev);

  rtnl_lock(); /* necessary around unregister_netdevice */

  unregister_netdevice(cb->netdev);

  rtnl_unlock();

  if (cb->txbuf_len_list != NULL)
    kfree(cb->txbuf_len_list);

#ifdef CHECK_ALLOC_TXBUF
  if (cb->dbg_txbuf != NULL)
    kfree(cb->dbg_txbuf);
#endif

  kfree(cb->netdev);
  kfree(cb);

} /* wl24n_card_stop */


/* == PROC wl24n_card_init ==
   initializes the driver instance: allocates memory for the control block,
   init. the cb and sends first request to card.
   Returns pointer to WL24Cb_t structure passed in later calls to (?) */
void *wl24n_card_init(uint32 dbg_mask, uint32 msg_to_dbg_mask,
                      uint32 msg_from_dbg_mask,
                      int BaseAddr, int irq, LLCType_t llctype, 
                      BSSType_t bsstype, uint8 *essid, int essid_len,
                      uint8 Channel, int *open_counter, char **dev_name, uint32 trace_mask)
{

  WL24Cb_t *cb = kmalloc(sizeof(WL24Cb_t), GFP_KERNEL);
  int err,i;

  if (dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s(open_counter %d)\n", __FUNCTION__, *open_counter);

  if (cb == NULL) {
    printk(KERN_WARNING "%s: cannot alloc %d byte\n",
           __FUNCTION__, sizeof(WL24Cb_t));
    return NULL;
  }

#if TRACE_NR_RECS > 0
  spin_lock_init(&cb->trace_spinlock);
  cb->trace_nr = cb->trace_next = 0;
  cb->trace_mask = trace_mask;
#endif

  cb->open_counter = open_counter;
  cb->card_started = 0;

  cb->txbuf_len_list = NULL;

#ifdef CHECK_ALLOC_TXBUF
  cb->dbg_txbuf = NULL;
#endif

  cb->netdev = kmalloc(sizeof(struct net_device), GFP_KERNEL);
  if (cb->netdev == NULL) {
    printk(KERN_WARNING "%s: cannot alloc %d byte\n", 
           __FUNCTION__, sizeof(WL24Cb_t));
    kfree(cb);
    return NULL;
  }

  //jal: without this memset we get a problem in rtnetlink_fill_ifinfo
  //     in filling dev->master ( == 0xf800 ?)
  memset(cb->netdev,0, sizeof(struct net_device));

  init_waitqueue_head(&cb->waitq);
  sema_init(&cb->ioctl_mutex,1);
  /* init netdevice 
     original sw: in wl24_cs.c 
     but we want to hide as much as possible from the PCMCIA part */

  cb->netdev->priv = cb; /* to get the cb in wl24_tx(),wl24n_open(),... */

  cb->netdev->hard_start_xmit = wl24n_tx;
  cb->netdev->get_stats = wl24n_get_stats;
  //cb->netdev->set_multicast_list = wl24n_set_multicast_list;
  cb->netdev->do_ioctl = wl24n_ioctl;
#ifdef WIRELESS_EXT
  cb->netdev->get_wireless_stats = wl24n_get_wireless_stats;
#endif /* WIRELESS_EXT */
  //cb->netdev->change_mtu = wl24n_change_mtu; /* TODO: try out if possible */

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,3,42))
  cb->netdev->tx_timeout = &wl24n_watchdog;
  cb->netdev->watchdog_timeo = TX_TIMEOUT;
#endif

  cb->netdev->init = wl24n_init;
  cb->netdev->open = wl24n_open;
  cb->netdev->stop = wl24n_close;

  cb->netdev->base_addr = BaseAddr;
  cb->netdev->irq = irq;

  memset(&cb->stats,0,sizeof(cb->stats));

  cb->name = cb->netdev->name;
  cb->dbg_mask = dbg_mask;
  cb->msg_to_dbg_mask = msg_to_dbg_mask;
  cb->msg_from_dbg_mask = msg_from_dbg_mask;
  cb->BaseAddr = BaseAddr;
  cb->llctype = llctype;
  cb->bsstype = bsstype;

  /* input essid is a simple string, convert it into TLV */
  cb->ESSID[0] = IE_ID_SSID;
  cb->ESSID[1] = MIN(essid_len,sizeof(cb->ESSID)-(1+1)-1);
  memcpy(cb->ESSID+2, essid, cb->ESSID[1]);
  cb->ESSID[1+1+cb->ESSID[1]] = '\0'; /* make it a C string */
  cb->Channel = Channel;

  cb->netdev->name[0] = '\0'; /* let init_etherdev choose a name eth%d */
  if (!init_etherdev(cb->netdev,0)) {
    printk(KERN_WARNING "init_etherdev failed\n");
    return NULL;
  }

  *dev_name = cb->netdev->name; /* pass the device name back to caller */
  //printk(KERN_DEBUG "init net device %p,%s\n", cb->netdev, cb->netdev->name);

  rtnl_lock(); /* necessary around register_netdevice ! 
                  (not with register_netdev ...) */
  if ((err=register_netdevice(cb->netdev)) < 0) {
    printk(KERN_WARNING "register_netdevice failed with %d\n", err);
    rtnl_unlock();
    return NULL;
  }
  rtnl_unlock();

  //printk(KERN_DEBUG "reg'ed net device %p\n", cb->netdev->name);
  /* or is register_netdev() necessary for kernel <= 2.3.x ??? */

  cb->state = state_invalid; /* gives a nicer debug output in next line */

  /* we cannot start the ScanReq here because in the PCMCIA module the IRQ handler
     isn't registered yet. -> do it in wl24n_open instead */

  /* init nickname with device name */
  i = MIN(strlen(cb->name), sizeof(cb->nickname)-1);
  memcpy(cb->nickname,cb->name,i);
  cb->nickname[i] = '\0';

  /* no WEP by default, but initialize the IV counter to a
     pseudo-random value */

  memset(&(cb->wepstate), 0, sizeof(cb->wepstate));
  cb->wepstate.ivval = jiffies;

#if IW_MAX_SPY > 0
  cb->iwspy_number = 0;
#endif

  cb->match_wanted_bssid = 0; /* initial: accept all BSSID */

  if (dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_card_init done\n", cb->name);
  
  return cb;
} /* end of wl24n_card_init */


/* == PROC wl24n_init == */
int wl24n_init(struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_init\n",cb->name);

  return 0;
} /* end of wl24n_init */

/* == PROC wl24n_set_multicast_list == */
static void wl24n_set_multicast_list (struct net_device *dev)
     __attribute__((unused));
     static void wl24n_set_multicast_list (struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: set_multicast_list() called: "
           "flags x%08x\n",cb->name,dev->flags);

  /* TODO: set multicast addr in card */
}

/* == PROC wl24n_open == */
int wl24n_open(struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_open\n",cb->name);

  if (!cb->card_started)
    /* restart_card was not successful */
    return -EBUSY;

  (*cb->open_counter)++;

#if 0 // we do this in mc2_config ...
  if ((ret=request_irq(dev->irq, wl24n_interrupt, 0, "mc2", dev)) < 0) {
    printk(KERN_WARNING "%s: cannot alloc irq %d, errno %d\n",
           cb->name, dev->irq, ret);
    return ret;
  }
#endif

  create_proc_entries(cb); /* create files in /proc/driver */

  MOD_INC_USE_COUNT;
  
  return 0;
}

/* == PROC wl24n_close == */
int wl24n_close(struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;
  int rc;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_close\n",cb->name);

  /* let the card service try to close the device first
     (look if it is a valid device, if a release was pending
     (DEV_STALE_CONFIG set in link->state), etc. */
  rc = wl24n_cs_close(cb);

  if (rc < 0)
    return rc;

  MOD_DEC_USE_COUNT;

  netif_device_detach(dev);

  delete_proc_entries(cb); /* create files in /proc/driver */

  if (--(*cb->open_counter) == 0) {

    /* old sw: Ack Interrupt ??? */
    //OutB(GCR_ECINT, cb->BaseAddr + NIC_GCR);
    
    /* mask interrupts from card */
    disable_card_interrupt(cb);
    if (dev->irq != 0)
      free_irq(dev->irq, dev);
  }

  return 0;
} /* end of wl24n_close */


/* == PROC wl24n_get_stats == */
struct net_device_stats *wl24n_get_stats (struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;

  // gets called too often
#if 0
  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_get_stats\n",cb->name);
#endif

  return &cb->stats;
}

#ifdef WIRELESS_EXT
/* == PROC wl24n_get_wireless_stats == */
struct iw_statistics *wl24n_get_wireless_stats (struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: wl24n_get_wireless_stats\n",cb->name);

  return &cb->wstats;
}
#endif

/* == PROC wl24n_watchdog == */
void wl24n_watchdog(struct net_device *dev)
{
  WL24Cb_t *cb = dev->priv;

#ifdef LOG_WL24N_WATCHDOG
  {
    Card_ESBQ_t cfm;
    uint8 sig;
    copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, 2, cb);
    copy_from_card(&sig, cfm.buf+2, 1, COPY_FAST, cb);
    printk(KERN_DEBUG "%s: GCR %02x ESBQCfm x%04x: owner %x buf %x signal %x\n",
           cb->name, InB(cb->BaseAddr+NIC_GCR), cb->ESBQCfm, cfm.owner, cfm.buf, sig);
  }
#endif


#if 0 // watchdog shall not run in other states
  if (cb->state != state_joined_ibss && cb->state != state_started_ibss &&
      cb->state != state_joined_ess)
    /* obey the timeout only if we are in a state where we can send
       ethernet packets. */
    return;
#endif

#ifdef RESET_ON_TX_TIMEOUT
  printk(KERN_WARNING "%s: tx timeout - resetting card!\n",cb->name);

  if (!restart_card(cb))
    printk(KERN_WARNING "%s: reset_card failed\n", cb->name);
  else {
    printk(KERN_DEBUG "%s: %s: Forced hard reset\n", cb->name, __FUNCTION__);
  }
#else
  printk(KERN_WARNING "%s: tx timeout - ignored.\n",cb->name);
#endif

} /* end of wl24n_watchdog */


#define hw_setmib(c,a,v,s) hw_mib(c,a,v,s, TRUE)
#define hw_getmib(c,a) hw_mib(c,a,NULL,0, FALSE)

/* == PROC hw_mib ==
   send a MIB SetReq or GetReq to card, delay process until
   SetCfm was received
   params val and sz are ignored for is_set_cmd == 0
   returns 0 for success or some (negative) errno to pass to
   ioctl caller
*/
int hw_mib(WL24Cb_t *cb, int attr, void *val, size_t sz, int is_set_cmd)
{
  int rc = 0;

  /* serialize MIB access */
  if (down_interruptible(&cb->ioctl_mutex))
    rc = -EINTR;
  else {
    cb->last_mibcfm_valid = 0;
    if (!(is_set_cmd ? SetMIBReq(cb, attr, val, sz) :
          GetMIBReq(cb, attr)))
      rc = -EBUSY; /* ??? better error value for "cannot send req to card" */
    else {
      if (wait_event_interruptible(cb->waitq, cb->last_mibcfm_valid != 0) ==
          -ERESTARTSYS)
        rc = -EINTR;
      else {
        assert(cb->last_mibcfm_valid != 0);
        /* no we've got the confirm in cb->last_mibcfm */
        assert(cpu_to_le16(cb->last_mibcfm.SignalID) == SetConfirm_ID ||
               cpu_to_le16(cb->last_mibcfm.SignalID) == GetConfirm_ID);
        assert(cpu_to_le16(cb->last_mibcfm.MibAttrib) == attr);
        if (cpu_to_le16(cb->last_mibcfm.MibStatus) != Status_Success) {
          /* ??? do we get Status_Success for successful completion ??? */
          rc = -EFAULT;
        }
      }
    }
    up(&cb->ioctl_mutex); /* leave mutex */
  }

  return rc;
} /* end of hw_mib */


/* == PROC hw_getbssid ==
   gets the BSS ID of a BSS we have joined (or zeros otherwise)
   returns 0 for failure, != 0 otherwise */
int hw_getbssid(WL24Cb_t *cb, void *dst)
{
  uint8 *bssid = (uint8 *)zeros;

  if (cb->state == state_joining || cb->state == state_assoc ||
      cb->state == state_auth || cb->state == state_joined_ess ||
      cb->state == state_joined_ibss) {
    /* we have found a BSS to join */
    assert(cb->currBSS >= 0 && cb->currBSS < NR_BSS_DESCRIPTIONS);
    assert(cb->BSSset[cb->currBSS].valid);
    bssid = cb->BSSset[cb->currBSS].BSSID;
  }

  memcpy(dst,bssid,ETH_ALEN);

  return 1;
}

/* == PROC hw_getcurrentchannel == */
int hw_getcurrentchannel(WL24Cb_t *cb)
{
  if (cb->state == state_joining || cb->state == state_assoc ||
      cb->state == state_auth || cb->state == state_joined_ess ||
      cb->state == state_joined_ibss) {
    /* we have found a BSS to join */
    assert(cb->currBSS >= 0 && cb->currBSS < NR_BSS_DESCRIPTIONS);
    assert(cb->BSSset[cb->currBSS].valid);
    /* get the channel from BSSset[] */
    return cb->BSSset[cb->currBSS].PHYpset[2];
  } else {
    /* still looking for a BSS */
    return cb->Channel; /* meaningless if cb->bsstype == Infrastructure ... */
  }
}

#if IW_MAX_SPY > 0
/* == PROC mc2_ioctl_setspy == */
static int mc2_ioctl_setspy(WL24Cb_t *cb, struct iw_point *srq)
{
  struct sockaddr address[IW_MAX_SPY];
  int number = srq->length;
  int i;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: ioctl(SIOCSIWSPY, number %d)\n", 
           cb->name, number);
  /* Check the number of addresses */
  if (number > IW_MAX_SPY)
    return -E2BIG;

  /* Get the data in the driver */
  if (srq->pointer) {
    if (copy_from_user(address, srq->pointer,
                       sizeof(struct sockaddr) * number))
      return -EFAULT;
  }

  cb->iwspy_number = 0;

  if (number > 0) {
    /* Extract the addresses */
    for (i = 0; i < number; i++) {
      memcpy(cb->iwspy[i].spy_address, address[i].sa_data,
             ETH_ALEN);
      /* Reset stats */
      cb->iwspy[i].spy_level = cb->iwspy[i].updated = 0;
    }

    /* Set number of addresses */
    cb->iwspy_number = number;
  }

  /* Time to show what we have done... */
  if (cb->dbg_mask & DBG_DEV_CALLS) {
    printk(KERN_DEBUG "%s: New spy list:\n", cb->name);
    for (i = 0; i < number; i++) {
      printk(KERN_DEBUG "%s: %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
             cb->name, i,
             cb->iwspy[i].spy_address[0], cb->iwspy[i].spy_address[1],
             cb->iwspy[i].spy_address[2], cb->iwspy[i].spy_address[3],
             cb->iwspy[i].spy_address[4], cb->iwspy[i].spy_address[5]);
    }
  }

  return 0;
} /* mc2_ioctl_setspy */


/* == PROC mc2_ioctl_getspy == */
static int mc2_ioctl_getspy(WL24Cb_t *cb, struct iw_point *srq)
{
  struct sockaddr address[IW_MAX_SPY];
  struct iw_quality spy_stat[IW_MAX_SPY];
  int number;
  int i;

  if (cb->dbg_mask & DBG_DEV_CALLS)
    printk(KERN_DEBUG "%s: ioctl(SIOCGIWSPY, number %d)\n", 
           cb->name, cb->iwspy_number);
#ifdef LOG_IWSPY
  printk(KERN_DEBUG "%s: iwspy_number %d\n", cb->name, cb->iwspy_number);
#endif
  srq->length = number = cb->iwspy_number;

  if ((number > 0) && (srq->pointer)) {
    /* Create address struct  and copy stats */
    for (i = 0; i < number; i++) {
      memcpy(address[i].sa_data, cb->iwspy[i].spy_address,
             ETH_ALEN);
      address[i].sa_family = AF_UNIX;
      /* ELSA MC-2: RSSI is not in dBm, no way to get noise and
         link quality ... */
      spy_stat[i].level = cb->iwspy[i].spy_level;
      spy_stat[i].updated = cb->iwspy[i].updated;
      cb->iwspy[i].updated = spy_stat[i].qual = 
        spy_stat[i].noise = 0;
    }

    /* Push stuff to user space */
    if(copy_to_user(srq->pointer, address,
                    sizeof(struct sockaddr) * number))
      return -EFAULT;
    if(copy_to_user(srq->pointer + (sizeof(struct sockaddr)*number),
                    &spy_stat, sizeof(struct iw_quality) * number))
      return -EFAULT;
  }
  return 0;
} /* mc2_ioctl_getspy */
#endif /* #if IW_MAX_SPY > 0 */

/* our private ioctl's (even numbers are get's (world exec.),
 odd numbers are set (root only) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
#  define SIOCIWFIRSTPRIV SIOCDEVPRIVATE
#endif

/* reset the card */
#define PRIV_IOCTL_RESET       (SIOCIWFIRSTPRIV + 0x0)

/* set debug masks */
#define PRIV_IOCTL_SETDBG_MASK (SIOCIWFIRSTPRIV + 0x2)
/* show current dbg masks  */
#define PRIV_IOCTL_GETDBG_MASK (SIOCIWFIRSTPRIV + 0x3)

/* send a SiteReq to card (results in the debug's) */
#define PRIV_IOCTL_SITEREQ     (SIOCIWFIRSTPRIV + 0x4)

/* show current cb->BSSset */
#define PRIV_IOCTL_BSSLIST     (SIOCIWFIRSTPRIV + 0x5)

/* set the LLCType */
#define PRIV_IOCTL_SET_LLC     (SIOCIWFIRSTPRIV + 0x6)
/* get the LLCType */
#define PRIV_IOCTL_GET_LLC     (SIOCIWFIRSTPRIV + 0x7)

/* send a MIB SetReq to card */
#define PRIV_IOCTL_MIBSET      (SIOCIWFIRSTPRIV + 0x8)
/* send a given MIB GetReq to card and display result */
#define PRIV_IOCTL_MIBGET      (SIOCIWFIRSTPRIV + 0x9)


/* == PROC wl24n_ioctl == */
int wl24n_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
  WL24Cb_t *cb = dev->priv;
  struct iwreq *wrq = (struct iwreq *) rq;
  int rc = 0;
  int index;
  int need_commit = 0; /* gets set to 1 if we must tell the card
                          some changed params */
  // Frequency list (map channels to frequencies)
  const long frequency_list[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
                                  2447, 2452, 2457, 2462, 2467, 2472, 2484 };
#define NUM_CHANNELS (sizeof(frequency_list)/sizeof(frequency_list[0]))

  switch (cmd)  {
    // Get name
  case SIOCGIWNAME:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWNAME\n", cb->name);
    strcpy(wrq->u.name,"IEEE 802.11-DS"); // is u.name in kernel address space ?
    break;

    // Set frequency/channel
  case SIOCSIWFREQ:
    {
      int chan = NUM_CHANNELS+1;

      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: ioctl SIOCSIWFREQ, freq.e %u freq.m %u\n", 
               cb->name, wrq->u.freq.e, wrq->u.freq.m);

      if (wrq->u.freq.e == 0 && wrq->u.freq.m <= 1000) {
        chan = wrq->u.freq.m; // setting by channel
      } else {
        int mult = 1, i;
        for(i=0; i < (6 - wrq->u.freq.e); i++)
          mult *= 10;
        for(i=0; i < NUM_CHANNELS; i++)
          if (wrq->u.freq.m == frequency_list[i] * mult) {
            chan = i+1;
            break;
          }
      }

      if ((chan < 1) || (chan > NUM_CHANNELS) ||
          !(1<<(chan-1) & cb->frdesc->channel_map)) {
        printk(KERN_DEBUG "%s: new channel value %d is invalid (e %u, m %d)\n", 
               cb->name, chan, wrq->u.freq.e, wrq->u.freq.m);
        rc = -EINVAL;
      } else {
        cb->Channel = chan;
        need_commit = 1;
        if (cb->dbg_mask & DBG_DEV_CALLS)
          printk(KERN_DEBUG "%s: ioctl SIOCSIWFREQ set new channel %d\n",
                 cb->name, cb->Channel);
      }
    }
    break;

    // Get frequency/channel
  case SIOCGIWFREQ:
#ifdef WEXT_USECHANNELS
    wrq->u.freq.m = hw_getcurrentchannel(cb);
    wrq->u.freq.e = 0;
#else
    wrq->u.freq.m = frequency_list[hw_getcurrentchannel(cb)-1] * 100000;
    wrq->u.freq.e = 1;
#endif
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWFREQ -> freq.m %u freq.e %u\n", 
             cb->name, wrq->u.freq.m, wrq->u.freq.e);
    break;

    // Set desired network name (ESSID)
  case SIOCSIWESSID:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWESSID, pointer %p flags %d length %d\n", 
             cb->name, wrq->u.data.pointer, wrq->u.data.flags, wrq->u.data.length);

    if (wrq->u.data.pointer) {
      /* Check if we asked for `any' */
      if(wrq->u.data.flags == 0) {
        cb->ESSID[0] = cb->ESSID[1] = cb->ESSID[2] = 0;
      } else {
        /* Check the size of the string */
        if(wrq->u.data.length > IW_ESSID_MAX_SIZE + 1) {
          rc = -E2BIG;
          break;
        }
        if (copy_from_user(&cb->ESSID[2],
                           wrq->u.data.pointer,
                           wrq->u.data.length)) {
          rc = -EFAULT;
          break;
        }
        cb->ESSID[0] = IE_ID_SSID;
        cb->ESSID[1] = wrq->u.data.length;

        /* strip a trailing '\0' in ESSID */
        if (cb->ESSID[1] > 0 && cb->ESSID[2+cb->ESSID[1]-1] == '\0')
          cb->ESSID[1]--;
        assert(cb->ESSID[1] <= IW_ESSID_MAX_SIZE);
        if (cb->ESSID[1] > IW_ESSID_MAX_SIZE)
          cb->ESSID[1] = IW_ESSID_MAX_SIZE;
        cb->ESSID[2+cb->ESSID[1]] = '\0'; /* make it printable */
      }
      need_commit = 1;
      if (cb->dbg_mask & DBG_DEV_CALLS) {
        printk(KERN_DEBUG "%s: ioctl SIOCSIWESSID set new ESSID (%d)%s (",
               cb->name, cb->ESSID[1], cb->ESSID+2);
        dumpk(cb->ESSID+2, cb->ESSID[1]);
        printk(")\n");
      }
    }
    break;

    // Get current network name (ESSID)
  case SIOCGIWESSID:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWESSID, pointer %p\n", 
             cb->name, wrq->u.data.pointer);
    if (wrq->u.data.pointer) {
      uint8 *essid;

      /* Get the essid that was set */
      if (cb->ESSID[1] == 0 && cb->currBSS >= 0) {
        assert(cb->currBSS < NR_BSS_DESCRIPTIONS && 
               cb->BSSset[cb->currBSS].valid);
          
        essid = cb->BSSset[cb->currBSS].SSID;
      } else
        essid = cb->ESSID;

      wrq->u.data.length = MIN(essid[1],IW_ESSID_MAX_SIZE) + 1;
      wrq->u.data.flags = 1; /* active */
      if (wrq->u.data.pointer)
        if (copy_to_user(wrq->u.data.pointer, essid+2, 
                         wrq->u.data.length)) 
          rc = -EFAULT;
    }
    break;

    // Get current Access Point (BSSID)
  case SIOCGIWAP:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWAP\n", cb->name);
    if (!hw_getbssid(cb, wrq->u.ap_addr.sa_data)) {
      rc = -EFAULT;
      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: SIOCGIWAP returns -EFAULT\n", cb->name);
    } else
      wrq->u.ap_addr.sa_family = ARPHRD_ETHER;
    break;
      
    /* Set desired nick name */
  case SIOCSIWNICKN:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWNICKN, pointer %p, length %d\n", 
             cb->name, wrq->u.data.pointer, wrq->u.data.length);
    if (wrq->u.data.pointer) {
      if (wrq->u.data.length > IW_ESSID_MAX_SIZE)
        rc = -E2BIG;
      else {
        char nbuf[IW_ESSID_MAX_SIZE+1];
        if (copy_from_user(nbuf, wrq->u.data.pointer, 
                           wrq->u.data.length))
          rc = -EFAULT;
        else {
          memcpy(cb->nickname,nbuf,wrq->u.data.length);
          cb->nickname[wrq->u.data.length] = '\0';
        }
      }
    }
    break;

    // Get current station name
  case SIOCGIWNICKN:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWNICKN, pointer %p\n",
             cb->name, wrq->u.data.pointer);
    if (wrq->u.data.pointer) {
      if (copy_to_user(wrq->u.data.pointer, cb->nickname, sizeof(cb->nickname)))
        rc = -EFAULT;
    }
    break;

    // Set the desired RTS threshold
  case SIOCSIWRTS:
    {
      int rthr = wrq->u.rts.value;
      Card_Word_t val;

      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: ioctl SIOCSIWRTS, value %d, disabled %d\n", 
               cb->name, wrq->u.rts.value, wrq->u.rts.disabled);

      if(wrq->u.rts.disabled)
        rthr = 2347;
      if((rthr < 0) || (rthr > 2347)) {
        rc = -EINVAL;
        break;
      }
      val = cpu_to_le16(rthr);
      rc = hw_setmib(cb, aRTSThreshold, &val, sizeof(val));
    }
    break;

    // get the current bitrate - we return constant 2 MBit
    // Is there an MIB attr to tell the true value ???
  case SIOCGIWRATE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWRATE\n", cb->name);
    wrq->u.bitrate.value = 2000000;
    wrq->u.bitrate.fixed = 0;
    wrq->u.bitrate.disabled = 0;
    break;

    /* set bitrate (we silently accept "auto" only) */
  case SIOCSIWRATE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWRATE, value %d, fixed %d\n", 
             cb->name, wrq->u.bitrate.value, wrq->u.bitrate.fixed);

    /* the value is in kbit/s */
    if (wrq->u.bitrate.value != -1)
      rc = -EOPNOTSUPP;
    break;

    // Get the current RTS threshold
  case SIOCGIWRTS:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWRTS\n", cb->name);
    if ((rc=hw_getmib(cb,aRTSThreshold)) == 0) {
      Card_Word_t val;
      memcpy(&val,cb->last_mibcfm.MibValue, sizeof(val));
        
      wrq->u.rts.value = le16_to_cpu(val);
      //printk(KERN_DEBUG "SIOCGIWRTS: got val x%x\n", wrq->u.rts.value);
      wrq->u.rts.disabled = (wrq->u.rts.value == 2347);
      wrq->u.rts.fixed = 1;
    }
    break;

    // Set the desired fragmentation threshold
  case SIOCSIWFRAG:
    {
      int fthr = wrq->u.frag.value;
      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: ioctl SIOCSIWFRAG, value %d, disabled %d\n", 
               cb->name, wrq->u.frag.value, wrq->u.frag.disabled);

      if(wrq->u.frag.disabled)
        fthr = 2346;
      if((fthr < 256) || (fthr > 2346)) {
        rc = -EINVAL;
      } else {
        Card_Word_t val;
        fthr &= ~0x1; // Get an even value
        val = cpu_to_le16(fthr);
        rc = hw_setmib(cb, aFragmentationThreshold, &val, sizeof(val));
      }
    }
    break;

    // Get the current fragmentation threshold
  case SIOCGIWFRAG:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWFRAG\n", cb->name);
    if ((rc=hw_getmib(cb,aFragmentationThreshold)) == 0) {
      Card_Word_t val;
      memcpy(&val,cb->last_mibcfm.MibValue, sizeof(val));
        
      wrq->u.frag.value = le16_to_cpu(val);
      //printk(KERN_DEBUG "SIOCGIWFRAG: got val x%x\n", wrq->u.rts.value);
      wrq->u.frag.disabled = (wrq->u.frag.value >= 2346);
      wrq->u.frag.fixed = 1;
    }
    break;

    /* Set operational mode: BSS_AnyBSS not possible here 
       (only via module parameter) */
  case SIOCSIWMODE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWMODE, mode %d\n", 
             cb->name, wrq->u.mode);

    switch (wrq->u.mode) {
    case IW_MODE_ADHOC:
      cb->bsstype = BSSType_Independent;
      break;
    case IW_MODE_INFRA:
      cb->bsstype = BSSType_Infrastructure;
      break;
    default:
      rc = -EINVAL;
    }
    need_commit = 1;
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWMODE set new bsstype %s\n",
             cb->name,
             cb->bsstype == BSSType_Infrastructure ? "Infrastructure" : 
             cb->bsstype == BSSType_Independent ? "Independent" :
             "AnyBSS");
    break;

    // Get port type
  case SIOCGIWMODE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWMODE\n", cb->name);
    wrq->u.mode = (cb->bsstype == BSSType_Infrastructure ? IW_MODE_INFRA :
                   IW_MODE_ADHOC);
    break;

    // Set the desired Power Management mode
    /* ELSA MC2: not sure if this works.
       Is "wake up on all DTIMs" == "no PM on MULTICAST" ??? */
  case SIOCSIWPOWER:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWPOWER, flags %d, disabled %d\n", 
             cb->name, wrq->u.power.flags, wrq->u.power.disabled);
#if 0
    // TODO: fill this out
    if(wrq->u.power.disabled) {

    } else {

      // Check mode
      switch(wrq->u.power.flags & IW_POWER_MODE) {
      case IW_POWER_UNICAST_R:
        break;
      case IW_POWER_ALL_R:
        break;
      case IW_POWER_ON: // None = ok
        break;
      default:  // Invalid
        rc = -EINVAL;
      }
      // not supported 
      if ((wrq->u.power.flags & IW_POWER_PERIOD) ||
          (wrq->u.power.flags & IW_POWER_TIMEOUT))
        rc = -EINVAL; // Invalid
    }
#else
    rc = -EOPNOTSUPP;
#endif
    break;

    // Get the power management settings
  case SIOCGIWPOWER:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWPOWER\n", cb->name);
    rc = hw_getmib(cb, aPowerMgmtEnable);
    /* correct MIB attribute ??? */
    /* is the returned value a byte ??? */
    wrq->u.power.disabled = (cb->last_mibcfm.MibValue[0] == 0);

    wrq->u.power.flags = 0;
    break;

    // Set WEP keys and mode
  case SIOCSIWENCODE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWENCODE\n", cb->name);

#ifdef LOG_IWENCODE
    printk(KERN_DEBUG "%s: old wepstate: encrypt %d txkeyid %d exclude_unencr %d\n",
           cb->name, cb->wepstate.encrypt, cb->wepstate.txkeyid,
           cb->wepstate.exclude_unencr);
    printk(KERN_DEBUG "%s: siwencode: enc.flags %08x pointer %p len %d\n",
           cb->name, wrq->u.encoding.flags, 
           wrq->u.encoding.pointer, wrq->u.encoding.length);
#endif

    if (cb->cardmode != 'H')
      {
        rc = -EOPNOTSUPP;
        goto out;
      }

    index = (wrq->u.encoding.flags & IW_ENCODE_INDEX) - 1;
    if ((index < 0) || (index >= WEP_CNT))
      index = index = cb->wepstate.txkeyid;

    if (wrq->u.encoding.pointer)
      {
        int len = wrq->u.encoding.length;

        if ((len < WEP_SMALL_KEY_SIZE) || (len > WEP_LARGE_KEY_SIZE)) {
          rc = -EINVAL;
          goto out;
        }

        memset(cb->wepstate.wepkeys[index].value, 0, 
               sizeof(cb->wepstate.wepkeys[index].value));

        if (copy_from_user(cb->wepstate.wepkeys[index].value, 
                           wrq->u.encoding.pointer, len)) {
          rc = -EFAULT;
          goto out;
        }

        cb->wepstate.wepkeys[index].length = 
          len > WEP_SMALL_KEY_SIZE ? WEP_LARGE_KEY_SIZE : WEP_SMALL_KEY_SIZE;

#ifdef LOG_IWENCODE
        printk(KERN_DEBUG "%s: new key index %d, len %d: ",
               cb->name, index, cb->wepstate.wepkeys[index].length);
        dumpk(cb->wepstate.wepkeys[index].value,cb->wepstate.wepkeys[index].length);
        printk("\n");
#endif

        cb->wepstate.encrypt = 1;
      }

    cb->wepstate.txkeyid = index;
    cb->wepstate.encrypt = ((wrq->u.encoding.flags & IW_ENCODE_DISABLED) == 0);
    if (wrq->u.encoding.flags & IW_ENCODE_RESTRICTED)
      cb->wepstate.exclude_unencr = 1;
    if (wrq->u.encoding.flags & IW_ENCODE_OPEN)
      cb->wepstate.exclude_unencr = 0;
    rc = 0;

#ifdef LOG_IWENCODE
    printk(KERN_DEBUG "%s: new wepstate: encrypt %d txkeyid %d exclude_unencr %d\n",
           cb->name, cb->wepstate.encrypt, cb->wepstate.txkeyid,
           cb->wepstate.exclude_unencr);
#endif

  out:    
    break;

    // Get the WEP keys and mode
  case SIOCGIWENCODE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWENCODE\n", cb->name);

    if (cb->cardmode != 'H')
      rc = -EOPNOTSUPP;
    else
      {
        index = (wrq->u.encoding.flags & IW_ENCODE_INDEX) - 1;
        if ((index < 0) || (index >= WEP_CNT))
          index = cb->wepstate.txkeyid;

        wrq->u.encoding.flags = (cb->wepstate.exclude_unencr) ? IW_ENCODE_RESTRICTED : IW_ENCODE_OPEN;
        if (!cb->wepstate.encrypt)
          wrq->u.encoding.flags |= IW_ENCODE_DISABLED;
        if (wrq->u.encoding.pointer)
          {
            if (copy_to_user(wrq->u.encoding.pointer, cb->wepstate.wepkeys[index].value, WEP_MAXLEN))
              rc = -EFAULT;
            wrq->u.encoding.flags |= (index + 1);
            wrq->u.encoding.length = cb->wepstate.wepkeys[index].length;
          }
        rc = 0;
      }
    break;

    // Get the current Tx-Power
  case SIOCGIWTXPOW:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWTXPOW\n", cb->name);
    rc = hw_getmib(cb, aCurrentTxPowerLevel);
    if (rc == 0) {
      /* get the tx power of level x in mW */
      rc = hw_getmib(cb, aTxPowerLevel1+cb->last_mibcfm.MibValue[0]-1);
      if (rc == 0) {
        wrq->u.txpower.value = cb->last_mibcfm.MibValue[0];
        wrq->u.txpower.fixed = 0; /* power control possible ??? */
        wrq->u.txpower.disabled = 0;  /* Can't turn off */
        /* which units has the result ? */
        wrq->u.txpower.flags = IW_TXPOW_MWATT;
      }
    }
    break;

    // Set the current Tx-Power
  case SIOCSIWTXPOW:
    {
      uint8 level = wrq->u.txpower.value;
      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: ioctl SIOCSIWTXPOW, value %d\n", 
               cb->name, wrq->u.txpower.value);
      /* TODO: unit conversion (read the table mW -> tx level once
         from firmware and hardcode it here) */
      rc = hw_setmib(cb, aCurrentTxPowerLevel,&level, sizeof(level));
    }
    break;

    // Get range of parameters
  case SIOCGIWRANGE:
    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCGIWRANGE\n", cb->name);
    if (wrq->u.data.pointer) {
      struct iw_range range;
      rc = verify_area(VERIFY_WRITE, wrq->u.data.pointer, 
                       sizeof(struct iw_range));
      if (rc)
        break;
      /* Set the length (very important for
       * backward compatibility) */
      wrq->u.data.length = sizeof(range);

      /* Set all the info we don't care or
       * don't know about to zero */
      memset(&range, 0, sizeof(range));

#if WIRELESS_EXT > 10  /* Set the Wireless Extension versions */
      range.we_version_compiled = WIRELESS_EXT;
      range.we_version_source = 10;
#endif /* WIRELESS_EXT > 10 */

      // Throughput is no way near 2 Mb/s !
      // This value should be :
      //  1.6 Mb/s for the 2 Mb/s card
      //  ~5 Mb/s for the 11 Mb/s card
      // Jean II
      range.throughput = 1.6 * 1024 * 1024;
      range.min_nwid = 0x0000;
      range.max_nwid = 0x0000;
      range.num_channels = 14;
        
      /* set range.freq[] and range.num_frequency */
      {
        int k = 0, i;
        for(i=0; i < IW_MAX_FREQUENCIES; i++) {
          if (cb->frdesc->channel_map & (1<<i)) {
            range.freq[k].i = i+1;  /* Set the list index */
            range.freq[k].m = frequency_list[i] * 100000;
            range.freq[k++].e = 1; /* frequency_list is in MHz ->
                                    * 10^5 * 10 */
          }
        }
        range.num_frequency = k;
      }

      range.sensitivity = 0;

      range.max_qual.qual = 0;
      range.max_qual.level = 63;
      range.max_qual.noise = 0;

      range.num_bitrates = 2;
      range.bitrate[0] = 1000000;
      range.bitrate[1] = 2000000;

      range.min_rts = 0;
      range.max_rts = 2347;
      range.min_frag = 256;
      range.max_frag = 2346;

      // WEP is not supported.
      range.num_encoding_sizes = 0;
      range.max_encoding_tokens = 0;

#if WIRELESS_EXT > 9
      /* Power Management */
      range.min_pmp = 0;    /* ??? */
      range.max_pmp = 65535000; /* ??? */
      range.pmp_flags = 0;
      range.pmt_flags = 0;
      range.pm_capa = 0;

      /* Transmit Power */
      range.txpower[0] = 17; /* ??? maybe more levels ??? */
      range.num_txpower = 1;
      range.txpower_capa = IW_TXPOW_DBM;
#endif /* WIRELESS_EXT > 9 */

      if (copy_to_user(wrq->u.data.pointer, &range,
                       sizeof(struct iw_range)))
        rc = -EFAULT;
    }
    break;

#if IW_MAX_SPY > 0
    /* ELSA MC2: no way to get quality of link and 
       noise level with firmware <= 2.0.6 */
    // Set the spy list
  case SIOCSIWSPY:
    rc = mc2_ioctl_setspy(cb, &wrq->u.data);
    break;

    // Get the spy list
  case SIOCGIWSPY:
    rc = mc2_ioctl_getspy(cb, &wrq->u.data);
    break;
#endif /* #if IW_MAX_SPY > 0 */

    // Get valid private ioctl calls
  case SIOCGIWPRIV:
    if (wrq->u.data.pointer)
      {
        struct iw_priv_args priv[] = {
          { PRIV_IOCTL_RESET, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
            0, "reset" }, /* param: int (0 for soft reset / 1 for hard) */

          { PRIV_IOCTL_MIBSET, IW_PRIV_TYPE_BYTE | (MAX_MIB_VALUE_SZ+1), 
            IW_PRIV_TYPE_INT | 1, "mibset"},
          /* param: first byte is the attribute code, rest is value,
             result: the status */

          { PRIV_IOCTL_MIBGET, IW_PRIV_TYPE_BYTE | 1 
            /* not fixed otherwise we don't get a user space buffer 
               for the return values (see iwpriv.c) */,
            IW_PRIV_TYPE_BYTE | MAX_MIB_VALUE_SZ, "mibget"},
          /* param: MIB attribute
             result: MIB value */

          { PRIV_IOCTL_GETDBG_MASK, 0, 
            IW_PRIV_TYPE_INT |IW_PRIV_SIZE_FIXED | 3, "getdbg"},
          /* results: dbg_mask, msg_from_dbg_mask, msg_to_dbg_mask */

          { PRIV_IOCTL_SETDBG_MASK, 
            IW_PRIV_TYPE_INT |IW_PRIV_SIZE_FIXED | 3,
            IW_PRIV_TYPE_INT |IW_PRIV_SIZE_FIXED | 3, "setdbg"},
          /* params & results: dbg_mask, msg_from_dbg_mask,
             msg_to_dbg_mask */

          { PRIV_IOCTL_SITEREQ, 0, 0, "sitereq"},

          { PRIV_IOCTL_BSSLIST, 0,
            IW_PRIV_TYPE_BYTE | sizeof(cb->BSSset),
            "bsslist"},
          /* results: copy of cb->BSSset[] */

          { PRIV_IOCTL_GET_LLC,
            0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_llc"},
          /* result: current LLC type */

          { PRIV_IOCTL_SET_LLC,
            IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_llc"},
          /* param: new LLC type */
        };

        wrq->u.data.length = sizeof(priv) / sizeof(priv[0]);
        if (copy_to_user(wrq->u.data.pointer, priv, sizeof(priv)))
          rc = -EFAULT;
      }
    break;

    // Force card reset
  case PRIV_IOCTL_RESET:
    // Only super-user can reset the card...
    if (!capable(CAP_NET_ADMIN)) {
      rc = -EPERM;
    } else {

      if (*((int *) wrq->u.name) > 0) {

        /* 'hard' reset (but all params [e.g. bsstype] remain) */
        if (!restart_card(cb))
          printk(KERN_WARNING "%s: reset_card failed\n", cb->name);
        else {
          printk(KERN_DEBUG "%s: Forced hard reset\n", cb->name);
        }

      } else {

#if 1
        rc = -EOPNOTSUPP;
#else
        // 'soft' reset
        if (!ResetReq(cb,FALSE,cb->MacAddress))
          printk(KERN_WARNING "%s: sending ResetReq failed\n",cb->name);
        else {
          printk(KERN_DEBUG "%s: Forced soft reset\n", cb->name);
          init_scanlist(cb); /* init. cb-> vars for initial scan */
          /* try to find all infrastructure BSS and IBSS for a 
             properly filled
             BSSset[] table. We match the correct BSS type later. */
          newstate(cb,state_scanning);

          /* reset statistics */
          memset(&cb->stats,0,sizeof(cb->stats));
# ifdef WIRELESS_EXT
          memset(&cb->wstats,0,sizeof(cb->wstats));
# endif

          ScanReq(cb, SCAN_MIN_CHANNEL_TIME,
                  SCAN_FIRST_RUN_MAX_CHANNEL_TIME,
                  BSSType_AnyBSS, ScanType_Active);
        }
#endif
      }
    }
    break;

    // send a SetReq to card and return the status
  case PRIV_IOCTL_MIBSET:
    {
      uint8 buf[1+MAX_MIB_VALUE_SZ];

      if (wrq->u.data.length == 0) {
        rc = -EINVAL;
        break;
      }

      if (copy_from_user(buf,wrq->u.data.pointer,wrq->u.data.length)) {
        rc = -EFAULT;
        printk(KERN_DEBUG "%s: ioctl PRIV_IOCTL_MIBSET failed to copy input from %p\n",
               cb->name, wrq->u.data.pointer);
        break;
      }
      rc = hw_setmib(cb, buf[0], buf+1, wrq->u.data.length-1);
      /* we ignore -EFAULT here, because hw_setmib has set this code only 
         if SetCfm_t.Status was not successful */
      if (rc == -EFAULT)
        rc = 0;
      if (rc == 0) {
        int status = le16_to_cpu(cb->last_mibcfm.MibStatus);
        if (copy_to_user(wrq->u.data.pointer,&status, sizeof(status))) {
          printk(KERN_DEBUG "%s: ioctl PRIV_IOCTL_MIBSET failed to copy status to %p\n",
                 cb->name, wrq->u.data.pointer);
          rc = -EFAULT;
        } else
          wrq->u.data.length = 1;
      }
    }
    break;

    // send an arbitrary GetReq to card and return the result
  case PRIV_IOCTL_MIBGET:
    {
      uint8 attr;
      if (copy_from_user(&attr,wrq->u.data.pointer,sizeof(attr))) {
        rc = -EFAULT;
        printk(KERN_DEBUG "%s: ioctl PRIV_IOCTL_MIBGET failed to copy input from %p\n",
               cb->name, wrq->u.data.pointer);
        break;
      }
      rc = hw_getmib(cb, attr);
      if (rc == 0) {
#if 0
        printk(KERN_DEBUG "%s: PRIV_IOCTL_MIBGET data: pointer %p length %d\n",
               cb->name, wrq->u.data.pointer, wrq->u.data.length);
#endif
        if (copy_to_user(wrq->u.data.pointer,cb->last_mibcfm.MibValue,
                         MAX_MIB_VALUE_SZ)) {
          printk(KERN_DEBUG "%s: ioctl PRIV_IOCTL_MIBGET failed to copy result to %p\n",
                 cb->name, wrq->u.data.pointer);
          rc = -EFAULT;
        } else
          wrq->u.data.length = MAX_MIB_VALUE_SZ;
      }
    }
    break;

  case PRIV_IOCTL_GETDBG_MASK:
    {
      uint32 m[3] = {cb->dbg_mask, cb->msg_from_dbg_mask,
                     cb->msg_to_dbg_mask};

      memcpy(wrq->u.name, m, sizeof(m));
      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: ioctl PRIV_IOCTL_GETDBG_MASK dbg masks: %08x %08x %08x\n",
               cb->name, m[0], m[1], m[2]);
    }
    break;

  case PRIV_IOCTL_SETDBG_MASK:
    if (!capable(CAP_NET_ADMIN)) {
      rc = -EPERM;
    } else {
      uint32 oldm[3] = {cb->dbg_mask, cb->msg_from_dbg_mask,
                        cb->msg_to_dbg_mask};
      uint32 m[3];
        
      /* where are the input values passed: in u.name or in u.data ??? */
      memcpy(m, wrq->u.name, sizeof(m));
      cb->dbg_mask = m[0];
      cb->msg_from_dbg_mask = m[1];
      cb->msg_to_dbg_mask = m[2];
      
      if (cb->dbg_mask & DBG_DEV_CALLS)
        printk(KERN_DEBUG "%s: ioctl PRIV_IOCTL_SETDBG_MASK new dbg masks: %08x %08x %08x\n",
               cb->name, cb->dbg_mask, cb->msg_from_dbg_mask,
               cb->msg_to_dbg_mask);
        
      if (copy_to_user(wrq->u.data.pointer, oldm,
                       sizeof(oldm)))
        rc = -EFAULT;
      else
        wrq->u.data.length = 3;
    }
    break;

    /* we send a SiteReq to card, result is in syslog */
  case PRIV_IOCTL_SITEREQ:
    /* switch debug for SiteCfm on */
    if (!capable(CAP_NET_ADMIN)) {
      rc = -EPERM;
    } else {
      cb->dbg_mask |= DBG_MSG_FROM_CARD;
      cb->msg_from_dbg_mask |= DBG_SITE_CFM;
      if (!SiteReq(cb))
        printk(KERN_WARNING "%s: sending SiteReq failed\n",cb->name);
    }
    break;
        
  case PRIV_IOCTL_BSSLIST:
    if (copy_to_user(wrq->u.data.pointer, cb->BSSset,
                     sizeof(cb->BSSset)))
      rc = -EFAULT;
    else
      wrq->u.data.length = sizeof(cb->BSSset);
    break;

    
  case PRIV_IOCTL_GET_LLC:
    *((int *)wrq->u.name) = cb->llctype;
    break;

  case PRIV_IOCTL_SET_LLC:
    if (!capable(CAP_NET_ADMIN)) {
      rc = -EPERM;
    } else {
      int t = *((int *)wrq->u.name);
      if (t != LLCType_WaveLan && t != LLCType_IEEE_802_11)
        rc = -EINVAL;
      else {
        cb->llctype = t;
        if (cb->dbg_mask & DBG_DEV_CALLS)
          printk(KERN_DEBUG "%s: new LLCType set: %d\n",
                 cb->name, cb->llctype);
        // we don't need commit, as this option just defines how to format tx/rx packets 
        //need_commit = 1; 
      }
    }
    break;

  case SIOCSIWAP: /* set MAC address of wanted AP */
    {
      /* iwconfig sends this broadcast address for "ap any"
         and a null address for "ap off" */
      const static uint8 broad_addr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
      const static uint8 null_addr[ETH_ALEN] = {0,0,0,0,0,0};

    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl SIOCSIWAP "
             "%02X:%02X:%02X:%02X:%02X:%02X\n", cb->name,
             (uint8)wrq->u.ap_addr.sa_data[0],(uint8)wrq->u.ap_addr.sa_data[1],
             (uint8)wrq->u.ap_addr.sa_data[2],(uint8)wrq->u.ap_addr.sa_data[3],
             (uint8)wrq->u.ap_addr.sa_data[4],(uint8)wrq->u.ap_addr.sa_data[5]);

      if (memcmp(wrq->u.ap_addr.sa_data, broad_addr, ETH_ALEN) &&
          memcmp(wrq->u.ap_addr.sa_data, null_addr, ETH_ALEN)) {
        /* we have a valid MAC address to match */
        cb->match_wanted_bssid = 1;
        memcpy(cb->wanted_bssid,wrq->u.ap_addr.sa_data,ETH_ALEN);
        need_commit = 1;
      } else {
        /* switch bssid matching off */
        if (cb->match_wanted_bssid)
          need_commit = 1;
        cb->match_wanted_bssid = 0;
      }
    }
    break;

    // All other calls are currently unsupported
  default:

    if (cb->dbg_mask & DBG_DEV_CALLS)
      printk(KERN_DEBUG "%s: ioctl(cmd=0x%x) - unknown\n",cb->name, cmd);

    rc = -EOPNOTSUPP;
  } /* switch (cmd) */

  if ((cb->dbg_mask & DBG_DEV_CALLS) && rc < 0)
    printk(KERN_DEBUG "%s: ioctl(x%x) failed with %d\n", cb->name, cmd, rc);

  if (need_commit) {
    if (!restart_card(cb))
      printk(KERN_WARNING "%s: restarting card failed\n",cb->name);
  }

  return rc;
} /* end of wl24n_ioctl */


#define BEACON_PERIOD 400 /* time between beacon frames in usec */
#define DTIM_PERIOD 1 /* beacon intervals between beacon frames with DTIM */
#define PROBE_DELAY 0x10 /* active scan & join: min. time to wait before 
                            Probe frame is sent */

/* bits in the CapabilityInfo field below (see 7.3.14 in [1]) */
#define CAP_ESS  0x0001 
#define CAP_IBSS 0x0002
#define CAP_CF_POLLABLE 0x0004
#define CAP_CF_POLL_REQ 0x0008
#define CAP_PRIVACY 0x0010

/* coding of supported rates (for IE "supported rates"):
 0x80 + rate in units of 500 kbit/s */
#define RATE_1MBIT 0x82
#define RATE_2MBIT 0x84

static const uint8 own_basic_rate_set[4] = {
  IE_ID_SUPPORTED_RATES, 2, RATE_1MBIT, RATE_2MBIT};
static const uint8 own_operational_rate_set[4] = {
  IE_ID_SUPPORTED_RATES, 2, RATE_1MBIT, RATE_2MBIT};

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 BSSType;
  uint16  BeaconPeriod;
  uint16  DTIMPeriod;
  uint16  ProbeDelay;
  uint16  CapabilityInfo;
  uint8 SSID[SIZE_OF_SSID];
  uint8 BSSBasicRateSet[10];
  uint8 OperationalRateSet[10];
  uint8 CFpset[8]; 
  uint8 PHYpset[3];
  uint8 IBSSpset[4]; /* contains the ATIM window parameter, see 7.3.2.7 in [1] */
} PACKED StartReq_t;

/* == PROC StartReq ==
   star a new BSS (see 10.3.10.2.1 in [1]) */
bool StartReq(WL24Cb_t *cb, uint8 channel, BSSType_t bsstype)
{
  StartReq_t Req;

  memset(&Req,0,sizeof(Req));

  /* the card has little endian mode and we must use
     copy_to_card because we mix bytes and words here */
  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = StartRequest_ID;
  Req.BSSType = bsstype;
  Req.BeaconPeriod = cpu_to_le16(BEACON_PERIOD);
  Req.DTIMPeriod = cpu_to_le16(DTIM_PERIOD);

  Req.ProbeDelay = cpu_to_le16(0); /* we start a beacon here,
                                      not an active scan ??? */

  Req.PHYpset[0] = IE_ID_DS_PARAM_SET;
  Req.PHYpset[1] = 1;
  Req.PHYpset[2] = channel;

  Req.CapabilityInfo = cpu_to_le16(CAP_IBSS); /* we start an IBSS */

  memcpy(Req.SSID, cb->ESSID, 1+1+cb->ESSID[1]);
  //memcpy(cb->KeepESSID, cb->ESSID, sizeof(cb->KeepESSID)); /* why ??? */

  /* set of rates each STA must support to join the BSS */
  memcpy(Req.BSSBasicRateSet, own_basic_rate_set, sizeof(own_basic_rate_set));

  /* set of rates a STA can use to talk to the BSS */
  memcpy(Req.OperationalRateSet, own_operational_rate_set, 
         sizeof(own_operational_rate_set));

  /* original sw: do not set IBSSpset (aka the ATIM window) ??? */
  Req.IBSSpset[0] = 6;
  Req.IBSSpset[1] = 2;
  Req.IBSSpset[2] = 10;
  Req.IBSSpset[3] = 0;

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_START_REQ))
    printk(KERN_DEBUG "%s: StartReq ch %d bsstype %d\n",
           cb->name, channel, bsstype);

#if 0 //jal: for testing only
  printk(KERN_DEBUG "%s: sending StartReq: ", __FUNCTION__);
  dumpk((uint8 *)&Req, sizeof(Req));
  printk("\n");
#endif

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of StartReq */


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 BSSType;
  uint16  ProbeDelay;
  uint16  MinChannelTime;
  uint16  MaxChannelTime;
  uint8 ChannelList[14];
  uint8  BSSID[6];
  uint8 SSID[SIZE_OF_SSID];
  uint8 ScanType;
} PACKED ScanReq_t;


/* == PROC ScanReq ==
   scan for BSS (see 10.3.2.1 in [1])
   min/max_channel_time: min/max time in TUs to spend on one channel */
bool  ScanReq(WL24Cb_t *cb, uint16 min_channel_time,
              uint16 max_channel_time, BSSType_t bsstype,
              ScanType_t scantype)
{
  ScanReq_t Req;

  memset(&Req,0,sizeof(Req)); /* needed ??? */

  /* the card has little endian mode and we must use
     copy_to_card because we mix bytes and words here */
  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = ScanRequest_ID;

  if (cb->scan_runs == 0) {
    /* we run the first scan with an empty SSID
       (to get most BSS into the list) and all other scans with the
       configured SSID, because a "closed network"
       won't answer to a probe with empty SSID */
    /* firmwares < 2.10 always use the ANY SSID even if we specify 
       another here (a bug) */
    Req.SSID[0] = IE_ID_SSID;
    Req.SSID[1] = 0;
  } else {
    memcpy(Req.SSID, cb->ESSID, 1+1+cb->ESSID[1]);
  }
 
  Req.ScanType = scantype;
  Req.ProbeDelay = cpu_to_le16(PROBE_DELAY);
  Req.MinChannelTime = cpu_to_le16(min_channel_time);
  Req.MaxChannelTime = cpu_to_le16(max_channel_time);

  assert(bsstype == BSSType_Infrastructure ||
         bsstype == BSSType_Independent  ||
         bsstype == BSSType_AnyBSS);

  Req.BSSType = bsstype;

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_SCAN_REQ)) {
    printk(KERN_DEBUG "%s: ScanReq ScanType %d BSSType %d SSID (%d)%s (",
           cb->name, Req.ScanType, Req.BSSType, Req.SSID[1], 
           Req.SSID[1] ? cb->ESSID+2 /*Req.SSID+2 is not \0 term.!*/ : 
           (uint8 *)"");
    dumpk(Req.SSID+2, Req.SSID[1]);
    printk(") min/max channel time %d/%d\n",
           min_channel_time, max_channel_time);
  }

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of ScanReq */


/* termination of join after that many beacon intervals */
#define JOIN_FAILURE_TIMEOUT 10

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint8 OperationalRateSet[10];
  uint16  Reserved2;
  uint16  Timeout;
  uint16  ProbeDelay;
  uint8 Timestamp[8];
  uint8 LocalTime[8];
  uint16  BeaconPeriod;
  uint16  DTIMPeriod;
  uint16  CapabilityInfo;
  uint8 BSSType;
  uint8  BSSID[6];
  uint8 SSID[1+1+32];
  uint8 PHYpset[3];
  uint8 CFpset[8];
  uint8 IBSSpset[4];
  uint8 BSSBasicRateSet[10];
} PACKED JoinReq_t;

/* == PROC JoinReq ==
   request to join a BSS, station is the index into cb->BSSset[]
 */
bool JoinReq(WL24Cb_t *cb, uint16 station)
{
  JoinReq_t Req;

  memset(&Req,0,sizeof(Req)); /* needed ??? */

  /* the card has little endian mode and we must use
     copy_to_card because we mix bytes and words here */
  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = JoinRequest_ID;

  Req.Timeout = cpu_to_le16(JOIN_FAILURE_TIMEOUT); /* new, not in orig. sw !!! */
  Req.ProbeDelay = cpu_to_le16(PROBE_DELAY);  /* new, not in orig. sw !!! */

  /* TODO: check if the BSS' basic rate set is included here ! */
  memcpy(Req.OperationalRateSet, own_operational_rate_set, 
         sizeof(Req.OperationalRateSet));  /* new, not in orig. sw !!! */

  /* copy the BSSDescription elements from the BSS set 
     (see 10.3.2.2.2 and 10.3.3.1.2 in [1]) */
  memcpy(Req.BSSID,cb->BSSset[station].BSSID,sizeof(Req.BSSID));

  if (memcmp(&cb->BSSset[station].SSID[2], zeros, 
             cb->BSSset[station].SSID[1]))
    /* just copy the BSS's SSID if it is not filled with \0 */
    memcpy(Req.SSID,cb->BSSset[station].SSID,sizeof(Req.SSID));
  else
    /* otherwise take the SSID specified by iwconfig / module parameter */
    memcpy(Req.SSID,cb->ESSID,sizeof(Req.SSID));

  Req.BSSType = cb->BSSset[station].BSSType;
  Req.BeaconPeriod = cpu_to_le16(cb->BSSset[station].BeaconPeriod);
  Req.DTIMPeriod = cpu_to_le16(cb->BSSset[station].DTIMPeriod);
  /* new, not in orig. sw !!! */
  memcpy(Req.Timestamp, cb->BSSset[station].Timestamp, sizeof(Req.Timestamp));
  /* new, not in orig. sw !!! */
  memcpy(Req.LocalTime, cb->BSSset[station].LocalTime, sizeof(Req.LocalTime));

  memcpy(Req.PHYpset, cb->BSSset[station].PHYpset, sizeof(Req.PHYpset));
  memcpy(Req.CFpset, cb->BSSset[station].CFpset, sizeof(Req.CFpset));
  memcpy(Req.IBSSpset, cb->BSSset[station].IBSSpset, sizeof(Req.IBSSpset));
  Req.CapabilityInfo = cpu_to_le16(cb->BSSset[station].CapabilityInfo);
  memcpy(Req.BSSBasicRateSet, cb->BSSset[station].BSSBasicRateSet,
         sizeof(Req.BSSBasicRateSet));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_JOIN_REQ)) {
    printk(KERN_DEBUG "%s: JoinReq ch %d cap x%04x "
           "BSSID %02x:%02x:%02x:%02x:%02x:%02x broadcasted SSID (%d)%s (",
           cb->name, Req.PHYpset[2],Req.CapabilityInfo,
           Req.BSSID[0],Req.BSSID[1],Req.BSSID[2],
           Req.BSSID[3],Req.BSSID[4],Req.BSSID[5],
           cb->BSSset[station].SSID[1], &cb->BSSset[station].SSID[2]);
    dumpk(cb->BSSset[station].SSID+2, cb->BSSset[station].SSID[1]);
    {
      /* make Req.SSID[2] \0 terminated */
      char buf[IW_ESSID_MAX_SIZE+1];
      assert(Req.SSID[1] <= IW_ESSID_MAX_SIZE);
      memcpy(buf, &Req.SSID[2], Req.SSID[1]);
      buf[Req.SSID[1]] = '\0';
      printk(") joined SSID (%d)%s (",
             Req.SSID[1], buf);
    }
    dumpk(Req.SSID+2,Req.SSID[1]);
    printk(")\n");
  }

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of JoinReq */


/* timeout in TU's for authentication */
#define AUTH_TIMEOUT 1000

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Type;
  uint16  Timeout;
  uint8 MacAddress[SZ_MAC_ADDR]; /* address of peer to auth. with */
} PACKED AuthReq_t; 

/* == PROC AuthReq == */
bool AuthReq(WL24Cb_t *cb, uint16 auth_type, uint16 auth_timeout,
             uint8 *bssid)
{
  AuthReq_t Req;

  memset(&Req,0,sizeof(Req)); /* needed ??? */

  /* the card has little endian mode and we must use
     copy_to_card because we mix bytes and words here */
  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = AuthRequest_ID;
  Req.Type = cpu_to_le16(auth_type);
  Req.Timeout = cpu_to_le16(auth_timeout);

  memcpy(Req.MacAddress, bssid, sizeof(Req.MacAddress));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_AUTH_REQ)) {
    printk(KERN_DEBUG "%s: AuthReq type %d "
           "BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
           cb->name, Req.Type,
           Req.MacAddress[0],Req.MacAddress[1],Req.MacAddress[2],
           Req.MacAddress[3],Req.MacAddress[4],Req.MacAddress[5]);
  }

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of AuthReq */


/* timeout for association in TU */
#define ASSOC_FAILURE_TIMEOUT 1000
/* number of beacon intervals to pass before STA awakes and listen for the next
   beacon */
#define ASSOC_LISTEN_INTERVAL 5
typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Timeout;
  uint16  CapabilityInfo;
  uint16  ListenInterval;
  uint8 MacAddress[SZ_MAC_ADDR];
} PACKED AssocReq_t;

/* == PROC AssocReq == */
bool AssocReq(WL24Cb_t *cb)
{
  AssocReq_t Req;
  uint16 caps;

  memset(&Req,0,sizeof(Req)); /* needed ??? */

  /* the card has little endian mode and we must use
     copy_to_card because we mix bytes and words here */
  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = AssocRequest_ID;
  Req.Timeout = cpu_to_le16(ASSOC_FAILURE_TIMEOUT);
  Req.ListenInterval = cpu_to_le16(ASSOC_LISTEN_INTERVAL);

  /* we must set the Privacy bit in the capabilites to assure an
     Agere-based AP with optional WEP transmits encrypted frames
     to us.  AP only set the Privacy bit in their capabilities
     if WEP is mandatory in the BSS! */

  caps = cb->BSSset[cb->currBSS].CapabilityInfo;
  if (cb->wepstate.encrypt)
    caps |= 0x10;
  Req.CapabilityInfo = cpu_to_le16(caps);

  memcpy(Req.MacAddress, cb->BSSset[cb->currBSS].BSSID,
         sizeof(Req.MacAddress));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_ASSOC_REQ)) {
    printk(KERN_DEBUG "%s: AssocReq BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
           cb->name,
           Req.MacAddress[0],Req.MacAddress[1],Req.MacAddress[2],
           Req.MacAddress[3],Req.MacAddress[4],Req.MacAddress[5]);
  }

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of AssocReq */

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
} PACKED ResyncReq_t;

/* == PROC ResyncReq == */
bool ResyncReq(WL24Cb_t *cb)
{
  ResyncReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = ResyncRequest_ID;

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_RESYNC_REQ))
    printk("%s: Sending ResyncReq\n", cb->name);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of ResyncReq */


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
} PACKED SiteReq_t;

/* == PROC SiteReq == 
  not used in original sw. try it out !*/
bool SiteReq(WL24Cb_t *cb)
{
  SiteReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = SiteRequest_ID;

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_SITE_REQ))
    printk("%s: Sending SiteReq\n", cb->name);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of SiteReq */

/* see 10.3.1.1 in [1] */
typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 PwrSave;
  uint8 WakeUp;
  uint8 ReceiveDTIMs;
} PACKED PowerMgtReq_t;

/* == PROC PowerMgtReq ==
  not used in original sw. try it out !
  My guess:
  - power_save: TRUE to enter power save mode
  - wakeup: if TRUE awake the MAC immediately
  - receive_dtims: if TRUE the STA awakes to receive all DTIMs */
bool PowerMgtReq(WL24Cb_t *cb, bool power_save, bool wakeup,
                 bool receive_dtims)
{
  PowerMgtReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = PowermgtRequest_ID; 
  Req.PwrSave = power_save;
  Req.WakeUp = wakeup;
  Req.ReceiveDTIMs = receive_dtims;

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_POWERMGT_REQ))
    printk("%s: Sending PowerMgtReq pwrsave %d wakeup %d rec_dtims %d\n",
           cb->name, Req.PwrSave, Req.WakeUp, Req.ReceiveDTIMs);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of PowerMgtReq */


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Reason;
  uint8  MacAddress[SZ_MAC_ADDR]; /* from which STA do we want to deauthenticate ? */
} PACKED DeauthReq_t;

/* == PROC DeauthReq == 
 see 10.3.5.1.2 in [1] */
bool DeauthReq(WL24Cb_t *cb, uint8 *macAddr, uint16 reason)
{
  DeauthReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = DeauthRequest_ID; 
  Req.Reason = cpu_to_le16(reason);
  memcpy(Req.MacAddress, macAddr, sizeof(Req.MacAddress));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_DEAUTH_REQ))
    printk("%s: DeauthReq reason x%x "
           "peer %02x:%02x:%02x:%02x:%02x:%02x\n",
           cb->name, le16_to_cpu(Req.Reason),
           Req.MacAddress[0],Req.MacAddress[1],Req.MacAddress[2],
           Req.MacAddress[3],Req.MacAddress[4],Req.MacAddress[5]);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of DeauthReq */

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Reason;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED DisassocReq_t;

/* == PROC DisassocReq == 
 see 10.3.8 in [1] */
bool DisassocReq(WL24Cb_t *cb, uint8 *macAddr, uint16 reason)
{
  DisassocReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = DisassocRequest_ID; 
  Req.Reason = cpu_to_le16(reason);
  memcpy(Req.MacAddress, macAddr, sizeof(Req.MacAddress));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_DISASSOC_REQ))
    printk("%s: DisAssocReq reason x%x "
           "peer %02x:%02x:%02x:%02x:%02x:%02x\n",
           cb->name, le16_to_cpu(Req.Reason),
           Req.MacAddress[0],Req.MacAddress[1],Req.MacAddress[2],
           Req.MacAddress[3],Req.MacAddress[4],Req.MacAddress[5]);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of DisassocReq */


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  MibAtrib;
} PACKED GetReq_t;

/* == PROC GetMIBReq == */
bool GetMIBReq(WL24Cb_t *cb, uint16 attrib)
{
  GetReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = GetRequest_ID; 
  Req.MibAtrib = cpu_to_le16(attrib);

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_GETMIB_REQ))
    printk(KERN_DEBUG "%s: GetMIBReq attr %d\n",
           cb->name, le16_to_cpu(Req.MibAtrib));

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of GetMIB */


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  MibAtrib;
  uint8  MibValue[MAX_MIB_VALUE_SZ]; /* original sw: only 2 bytes long ??? */
} PACKED SetReq_t;

/* == PROC SetMIBReq == 
  be aware that all values > 8 bit must be stored in little endian in *src 
  by the caller ! */
bool SetMIBReq(WL24Cb_t *cb, uint16 attr, void *src, size_t sz)
{
  SetReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = SetRequest_ID; 
  Req.MibAtrib = cpu_to_le16(attr);

  assert(sizeof(Req.MibValue) >= sz);
  memcpy(Req.MibValue, src, MIN(sizeof(Req.MibValue),sz));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_SETMIB_REQ))
    printk("%s: SetMIBReq attr. %d val x%02x%02x%02x%02x..\n",
           cb->name, le16_to_cpu(Req.MibAtrib),
           Req.MibValue[0],Req.MibValue[1],Req.MibValue[2],
           Req.MibValue[3]);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of SetMIBReq */


#if 0 // we don't know the SignalID for ResetReq 
typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint8 SetDefaultMIB;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED ResetReq_t;

/* == PROC ResetReq == 
 This proc. tries to reset the MAC by sending it a signal.
 There is another procedure to completely reset the card&firmware. */
bool ResetReq(WL24Cb_t *cb, bool SetDefaultMIB, uint8 *macAddr)
{
  ResetReq_t Req;

  Req.NextBlock = cpu_to_le16(0);
  Req.SignalID = ResetRequest_ID; 
  Req.SetDefaultMIB = SetDefaultMIB;
  memcpy(Req.MacAddress,macAddr,sizeof(Req.MacAddress));

  if ((cb->dbg_mask & DBG_MSG_TO_CARD) &&
      (cb->msg_to_dbg_mask & DBG_RESET_REQ))
    printk("%s: ResetReq set default MIB %d " 
           "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
           cb->name, Req.SetDefaultMIB,
           Req.MacAddress[0],Req.MacAddress[1],Req.MacAddress[2],
           Req.MacAddress[3],Req.MacAddress[4],Req.MacAddress[5]);

  /* send the request */
  return request_to_card(cb,&Req,sizeof(Req));
} /* end of ResetReq */

#endif //#if 0 // we don't know the SignalID for ResetReq 

/* == RX FROM CARD == */

/* == PROC cfm_avail ==
   check if an ESBQCfm is available from card. If yes
   return its buffer address, otherwise return 0. */
Card_Word_t cfm_avail(WL24Cb_t *cb)
{
  Card_ESBQ_t cfm;
  Card_Word_t ret = 0;

  if (was_card_removed(cb))
    return 0;

  copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);

  /* re-read the entry:
     it seems that the firmware 2.6 sometimes under heavy load
     writes the owner bit _before_ it sets the correct value
     in the buf field ... (maybe it did not disable interrupts there ?) */
  if (cfm.owner & ESBQ_OWNED_BY_DRV) {
    copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);
    ret = cfm.buf;
  }

#ifdef LOG_CFM_AVAIL
  printk(KERN_DEBUG "%s: %s: ESBQCfm %x: owner %x buf %x\n",
         cb->name, __FUNCTION__, cb->ESBQCfm,  cfm.owner, cfm.buf);
#endif

  return ret;
} /* end of cfm_avail */


/* == PROC cfm_done ==
   called after an ESBQCfm was processed to give it back to
   the firmware and increase the ESBQCfm pointer in cb */
void cfm_done(WL24Cb_t *cb)
{
  Card_ESBQ_t cfm;

  if (was_card_removed(cb))
    return;

  copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);

  if (!(cfm.owner & ESBQ_OWNED_BY_DRV)) {

    /* I saw this error once, but couldn't reproduce it... */
    printk(KERN_WARNING "%s: %s owner bit unset in ESBQCfm @"
           "x%04x: owner x%x buf x%x\n",
           cb->name, __FUNCTION__, cb->ESBQCfm, cfm.owner, cfm.buf);

    copy_words_from_card((uint16 *)&cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);
    printk(KERN_WARNING "%s: %s re-read ESBQCfm @ x%04x: owner x%x buf x%x\n",
           cb->name, __FUNCTION__, cb->ESBQCfm, cfm.owner, cfm.buf);
  }

  if (cfm.owner & ESBQ_OWNED_BY_DRV) {
    cfm.owner &= 0xff; /* old sw does delete the whole byte, not only
                          the set bit ??? */
    copy_words_to_card(cb->ESBQCfm, (uint16 *)&cfm, SZ_ESBQ_W, cb);
  }

  /* set cb->ESBQCfm to next buffer */
  cb->ESBQCfm += sizeof(Card_ESBQ_t);
  if (cb->ESBQCfm >= cb->ESBQCfmEnd)
    cb->ESBQCfm = cb->ESBQCfmStart;

#ifdef LOG_CFM_DONE
  printk(KERN_DEBUG "%s: %s: next ESBQCfm %x (ESBQCfmStart %x)\n",
         cb->name, __FUNCTION__, cb->ESBQCfm, cb->ESBQCfmStart);
#endif

} /* end of cfm_done */


/* values in Reason field from peer station 
   see 7.3.1.7 in [1] */
typedef enum {
  Reason_Unspecified = 1,
  Reason_PrevAuthNoLongerValid = 2,
  Reason_DeauthStationLeavingIBSS = 3,
  Reason_DisassocInactivity = 4,
  Reason_DisassocTooManyAssocAtAP = 5,
  Reason_Class2FromNonAuthStation = 6,
  Reason_Class3FromNonAssocStation = 7,
  Reason_DisassocStationLeavingBSS = 8,
  Reason_AssocReqFromNonAuthStation = 9,
} Reason_t;


typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Data;
  uint8 Status;
  uint8 Priority;
  uint8 ServiceClass;
} PACKED MdCfm_t;

/* MdInd starts with a RxHeader_t */       
typedef struct {
  RxFrameLinkHeader_t flh; /* 5 byte */
  uint8   RxNextFrame;
  uint8   RxNextFrame1;
  uint8   RSSI;
  uint8   Time[8];
  uint8   Signal;
  uint8   Service;
  uint16  Length;
  uint16  CRC16;
  uint16  FrameControl;
  uint16  Duration;    /* Duration,Address1-3 are counted in
                          Length field above and in Size of MdInd ! */
  uint8   Address1[SZ_MAC_ADDR];
  uint8   Address2[SZ_MAC_ADDR];
  uint8   Address3[SZ_MAC_ADDR];
  uint16  Sequence;
  //  uint8   Address4[SZ_MAC_ADDR]; /* used for payload, not address4 */
} PACKED RxHeader_t;

/* we must subtract this from RxHeader.Length resp. MdInd.Size
   to get the real payload size as described in the comment above
   jal: guess: +4 for the 32 bit FCS at the end of transmission (see [1], pg. 44) */
#define RXHEADER_HEADER_SIZE \
   (sizeof(RxHeader_t)-offsetof(RxHeader_t,FrameControl)+4)

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Routing;
  uint16  Data;
  uint16  Size;
  uint8 Reception;
  uint8 Priority;
  uint8 ServiceClass;
  uint8 DAddr[SZ_MAC_ADDR];
  uint8 SAddr[SZ_MAC_ADDR];
} PACKED MdInd_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
  uint8 Timestamp[8];
  uint8 LocalTime[8];
  uint16  BeaconPeriod;
  uint16  DTIMPeriod;
  uint16  CapabilityInfo; /* bit1 - infrastructure mode, bit2 - ad-hoc mode */
  uint8 BSSType;
  uint8 BSSID[SZ_MAC_ADDR];
  uint8 SSID[SIZE_OF_SSID];
  uint8 PHYpset[3];
  uint8 CFpset[8];
  uint8 IBSSpset[4];
  uint8 BSSBasicRateSet[10];
  uint8 RSSI;
} PACKED ScanCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
} PACKED JoinCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
} PACKED StartCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Type;
  uint16  Status;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED AuthCfm_t;

/* only used in AP ! */
typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Type;
  uint8 MacAddress[SZ_MAC_ADDR];
} PACKED AuthInd_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED DeauthCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Reason;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED DeauthInd_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
} PACKED AssocCfm_t;

/* only used on AP side ! */
typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 MacAddress[SZ_MAC_ADDR];
} PACKED AssocInd_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
} PACKED DisassocCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Reason;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED DisassocInd_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  MibStatus;
  uint16  MibAttrib;
} PACKED SetCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
} PACKED PowerMgtCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Status;
} PACKED ReassocCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint8  MacAddress[SZ_MAC_ADDR];
} PACKED ReassocInd_t;

typedef struct {
  uint16  NextBlock;
  uint8   SignalID;
  uint8   Status;
} PACKED ResyncCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8   SignalID;
  uint8   Reserved;
  uint16  Status;
  uint8   RSSI[101];
} PACKED SiteCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8   SignalID;
  uint8   Status;
} PACKED SaveCfm_t;

/* no idea about the struct but the first two elems */
typedef struct {
  uint16  NextBlock;
  uint8   SignalID;
  uint8   unknown[32];
} PACKED RFtestCfm_t;

typedef struct {
  uint16  NextBlock;
  uint8 SignalID;
  uint8 Reserved;
  uint16  Data;
  uint8 Status;
  uint8 Priority;
  uint8 ServiceClass;
} PACKED MdConfirm_t;

#ifndef DISABLE_DEBUG_RX_MSG
/* == PROC debug_msg_from_card == */
void debug_msg_from_card(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{
  if ((cb->dbg_mask & DBG_MSG_FROM_CARD) == 0)
    return;

  switch (sigid) {

  case Alarm_ID:
    if (cb->msg_from_dbg_mask & DBG_ALARM)
      printk(KERN_DEBUG "%s: Alarm from card\n",cb->name);
#if TRACE_NR_RECS > 0
    if (cb->trace_mask & (1 << TRACE_MSG_RCV)) {
      uint8 buf[2];
      buf[0] = sigid;
      buf[1] = state2id(cb->state);
      trace_add(cb, TRACE_MSG_RCV, buf, 2);
    }
#endif
    break;

  case MdConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_MDCFM) ||
        (cb->msg_from_dbg_mask & 
         (DBG_UNSUCC_MDCFM_OTHER|DBG_UNSUCC_MDCFM_FAIL)) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      MdCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == MdConfirm_ID);
      if ((cb->msg_from_dbg_mask & DBG_MDCFM) || 
          ((cb->msg_from_dbg_mask & DBG_UNSUCC_MDCFM_OTHER) && 
           (cfm.Status != StatusMdCfm_Success) &&
           (cfm.Status != StatusMdCfm_Fail)) ||
          ((cb->msg_from_dbg_mask & DBG_UNSUCC_MDCFM_FAIL) && 
           (cfm.Status == StatusMdCfm_Fail)))
        printk(KERN_DEBUG "%s: MdCfm status %d prio %d serviceclass %d\n",
               cb->name, cfm.Status, cfm.Priority, cfm.ServiceClass);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 7);
#endif
    }
    break;

  case MdIndicate_ID:
    if ((cb->msg_from_dbg_mask & DBG_MDIND) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      MdInd_t ind;
      RxHeader_t rxhead;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == MdIndicate_ID);

      /* read rx header */
      copy_from_card(&rxhead, ind.Data, sizeof(rxhead), COPY_FAST, cb);

      if (cb->msg_from_dbg_mask & DBG_MDIND)
        printk(KERN_DEBUG "%s: MdInd reception %d prio %d serviceclass %d RSSI %d "
               " dest %02x:%02x:%02x:%02x:%02x:%02x "
               " src %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name, ind.Reception, ind.Priority, ind.ServiceClass,
               rxhead.RSSI,
               ind.DAddr[0],ind.DAddr[1],ind.DAddr[2],ind.DAddr[3],
               ind.DAddr[4],ind.DAddr[5],
               ind.SAddr[0],ind.SAddr[1],ind.SAddr[2],ind.SAddr[3],
               ind.SAddr[4],ind.SAddr[5]);

      if (cb->msg_from_dbg_mask & DBG_MDIND_HEADER) {

        printk(KERN_DEBUG "%s: RxHd Service %x Length %x FrCtrl %x Duration %x\n",
               cb->name, rxhead.Service, le16_to_cpu(rxhead.Length),
               le16_to_cpu(rxhead.FrameControl),
               le16_to_cpu(rxhead.Duration));
    
        printk(KERN_DEBUG "%s: RxHd Addr1 %02x:%02x:%02x:%02x:%02x:%02x "
               "Addr2 %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name,
               rxhead.Address1[0],rxhead.Address1[1],rxhead.Address1[2],
               rxhead.Address1[3],rxhead.Address1[4],rxhead.Address1[5],
               rxhead.Address2[0],rxhead.Address2[1],rxhead.Address2[2],
               rxhead.Address2[3],rxhead.Address2[4],rxhead.Address2[5]);

        printk(KERN_DEBUG "%s: RxHd Addr3 %02x:%02x:%02x:%02x:%02x:%02x "
               "Sequence %x\n",
               cb->name,
               rxhead.Address3[0],rxhead.Address3[1],rxhead.Address3[2],
               rxhead.Address3[3],rxhead.Address3[4],rxhead.Address3[5],
               le16_to_cpu(rxhead.Sequence));
      }

      /* output first 32 bytes of data */
      if (cb->msg_from_dbg_mask & DBG_MDIND_DATA) {
        uint8 buf[32];
        int i;
        copy_from_card(buf, ind.Data+sizeof(RxHeader_t), sizeof(buf),
                       COPY_FAST, cb);
        printk(KERN_DEBUG "%s: MdInd Data ", cb->name);
        for(i=0; i < sizeof(buf); i++) printk("%02x",buf[i]);
        printk("\n");
      }
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV)) {
        uint8 buf[1+6+6+2+1];
        buf[0] = ind.SignalID;
        memcpy(buf+1, ind.DAddr, 6);
        memcpy(buf+7, ind.SAddr, 6);
        memcpy(buf+13, &rxhead.Length, 2);
        buf[15] = rxhead.RSSI;
        trace_add(cb, TRACE_MSG_RCV, buf, sizeof(buf));
      }
#endif
    } /* if (cb->msg_from_dbg_mask & DBG_MDIND) */
    break;

  case AssocConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_ASSOC_CFM) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      AssocCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == AssocConfirm_ID);

      if (cb->msg_from_dbg_mask & DBG_ASSOC_CFM)
        printk(KERN_DEBUG "%s: AssocCfm status %d\n",
               cb->name, le16_to_cpu(cfm.Status));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 4);
#endif
    }
    break;

  case AssocIndicate_ID:
    if ((cb->msg_from_dbg_mask & DBG_ASSOC_IND) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      AssocInd_t ind;
      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == AssocIndicate_ID);

      if (cb->msg_from_dbg_mask & DBG_ASSOC_IND)
        printk(KERN_DEBUG "%s: AssocIndicate %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name,
               ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
               ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &ind.SignalID, 7);
#endif
    }
    break;
    
  case AuthConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_AUTH_CFM) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      AuthCfm_t cfm;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == AuthConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_AUTH_CFM)
        printk(KERN_DEBUG "%s: AuthCfm  type %d status %d "
               "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name, le16_to_cpu(cfm.Type), le16_to_cpu(cfm.Status),
               cfm.MacAddress[0],cfm.MacAddress[1],cfm.MacAddress[2],
               cfm.MacAddress[3],cfm.MacAddress[4],cfm.MacAddress[5]);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 12);
#endif
    }
    break;

  case AuthIndicate_ID:
    if ((cb->msg_from_dbg_mask & DBG_AUTH_IND) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      AuthInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == AuthIndicate_ID);
      if (cb->msg_from_dbg_mask & DBG_AUTH_IND)
        printk(KERN_DEBUG "%s: AuthInd  type %d "
               "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name, le16_to_cpu(ind.Type),
               ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
               ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &ind.SignalID, 10);
#endif
    }
    break;

  case DeauthConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_DEAUTH_CFM) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      DeauthCfm_t cfm;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == DeauthConfirm_ID);

      if (cb->msg_from_dbg_mask & DBG_DEAUTH_CFM)
        printk(KERN_DEBUG "%s: DeauthCfm  status %d "
               "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name, le16_to_cpu(cfm.Status),
               cfm.MacAddress[0],cfm.MacAddress[1],cfm.MacAddress[2],
               cfm.MacAddress[3],cfm.MacAddress[4],cfm.MacAddress[5]);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 10);
#endif
    }
    break;

  case DeauthIndicate_ID:
    if ((cb->msg_from_dbg_mask & DBG_DEAUTH_IND) ||
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      DeauthInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == DeauthIndicate_ID);
      if (cb->msg_from_dbg_mask & DBG_DEAUTH_IND)
        printk(KERN_DEBUG "%s: DeauthInd reason %d "
               "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name, le16_to_cpu(ind.Reason),
               ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
               ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &ind.SignalID, 10);
#endif
    }
    break;

  case DisassocConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_DISASSOC_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      DisassocCfm_t cfm;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == DisassocConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_DISASSOC_CFM)
        printk(KERN_DEBUG "%s: DisassocCfm  status %d\n",
               cb->name, le16_to_cpu(cfm.Status));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 4);
#endif
    }
    break;

  case DisassocIndicate_ID:
    if ((cb->msg_from_dbg_mask & DBG_DISASSOC_IND) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      DisassocInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == DisassocIndicate_ID);
      if (cb->msg_from_dbg_mask & DBG_DISASSOC_IND)
        printk(KERN_DEBUG "%s: DisassocInd reason %d "
               "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name, le16_to_cpu(ind.Reason),
               ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
               ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &ind.SignalID, 10);
#endif
    }
    break;

  case GetConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_GET_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      GetCfm_t cfm;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == GetConfirm_ID);

      if (cb->msg_from_dbg_mask & DBG_GET_CFM) {
        int i;
        printk(KERN_DEBUG "%s: GetCfm  status %d attr %d val ",
               cb->name, le16_to_cpu(cfm.MibStatus),le16_to_cpu(cfm.MibAttrib));
        for(i=0;i<32;i++) printk("%02x",cfm.MibValue[i]);
        printk("\n");
      }

#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 10);
#endif
    }
    break;

  case JoinConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_JOIN_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))){
      JoinCfm_t cfm;
      uint16 status;
      BSSDesc_t *bss = &cb->BSSset[cb->currBSS];

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == JoinConfirm_ID);
      status = le16_to_cpu(cfm.Status);
      if (cb->msg_from_dbg_mask & DBG_JOIN_CFM) {
        if (status != Status_Success)
          printk(KERN_DEBUG "%s: JoinCfm failed status %d\n", cb->name, status);
        else {
          printk(KERN_DEBUG "%s: Joining BSSID: %02x:%02x:%02x:%02x:%02x:%02x "
                 "SSID len (%d)%s (",
                 cb->name,
                 bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
                 bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
                 bss->SSID[1], bss->SSID+2);
          dumpk(bss->SSID+2, bss->SSID[1]);
          printk(") chan %d cap x%04x rssi %d\n",
                 bss->PHYpset[2],
                 bss->CapabilityInfo, bss->ScanRSSI);
        }
      }
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 4);
#endif
    }
    break;

  case PowermgtConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_POWERMGT_CFM)  || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      PowerMgtCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == PowermgtConfirm_ID);

      if (cb->msg_from_dbg_mask & DBG_POWERMGT_CFM)
        printk(KERN_DEBUG "%s: PowerMgtCfm  status %d\n",
               cb->name, le16_to_cpu(cfm.Status));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 4);
#endif
    }
    break;

  case ReassocConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_REASSOC_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      ReassocCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == ReassocConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_REASSOC_CFM)
        printk(KERN_DEBUG "%s: ReassocCfm  status %d\n",
               cb->name, le16_to_cpu(cfm.Status));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 4);
#endif
    }
    break;

  case ReassocIndicate_ID:
    if ((cb->msg_from_dbg_mask & DBG_REASSOC_IND) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      ReassocInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == ReassocIndicate_ID);
      if (cb->msg_from_dbg_mask & DBG_REASSOC_IND) {
        printk(KERN_DEBUG "%s: ReassocInd "
               "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               cb->name,
               ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
               ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);
      }
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &ind.SignalID, 8);
#endif
    }
    break;

  case ScanConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_SCAN_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      ScanCfm_t cfm;
      uint16 status;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == ScanConfirm_ID);
      status = le16_to_cpu(cfm.Status);
      if (cb->msg_from_dbg_mask & DBG_SCAN_CFM) {
        if (status != Status_Success)
          printk(KERN_DEBUG "%s: ScanCfm status %d\n", cb->name, status);
        else {
          char sbuf[33]; /* copy of cfm.SSID for printing */
          /* add trailing '\0' at ssid copy  */
          memcpy(sbuf,&cfm.SSID[2],MIN(sizeof(sbuf)-1,cfm.SSID[1]));
          sbuf[MIN(sizeof(sbuf)-1,cfm.SSID[1])] = '\0';

          printk(KERN_DEBUG "%s: ScanCfm chan %d cap x%04x rssi %d "
                 "BSSID: %02x:%02x:%02x:%02x:%02x:%02x "
                 "SSID (%d)%s (",
                 cb->name, cfm.PHYpset[2], le16_to_cpu(cfm.CapabilityInfo),
                 cfm.RSSI,
                 cfm.BSSID[0],cfm.BSSID[1],cfm.BSSID[2],
                 cfm.BSSID[3],cfm.BSSID[4],cfm.BSSID[5],
                 cfm.SSID[1], sbuf);
          dumpk(&cfm.SSID[2],cfm.SSID[1]);
          printk(")\n");
        }
      } /* if (cb->msg_from_dbg_mask & DBG_SCAN_CFM) */

#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV)) {
#define FIXED_LEN (1+2+1+2+SZ_MAC_ADDR+1)
        uint8 buf[FIXED_LEN+32];
        int ssid_len = MIN(32,cfm.SSID[1]);
        buf[0] = cfm.SignalID;
        memcpy(buf+1,&cfm.Status, 2);
        if (le16_to_cpu(cfm.Status) == Status_Success) {
          buf[3] = cfm.BSSType;
          memcpy(buf+4,&cfm.CapabilityInfo,2);
          memcpy(buf+6,cfm.BSSID,6);
          buf[12] = cfm.PHYpset[2];
          memcpy(buf+FIXED_LEN, cfm.SSID+2, ssid_len);
          trace_add(cb, TRACE_MSG_RCV, buf, FIXED_LEN+ssid_len);
        } else
          trace_add(cb, TRACE_MSG_RCV, buf, 3);

#undef FIXED_LEN
      } 
#endif
    }
    break;


  case SetConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_SET_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      SetCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == SetConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_SET_CFM)
        printk(KERN_DEBUG "%s: SetCfm  status %d attr %d\n",
               cb->name, le16_to_cpu(cfm.MibStatus),le16_to_cpu(cfm.MibAttrib));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 6);
#endif
    }
    break;

  case StartConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_START_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      StartCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == StartConfirm_ID);

      if (cb->msg_from_dbg_mask & DBG_START_CFM) {
        if (le16_to_cpu(cfm.Status) == Status_Success)
          printk(KERN_DEBUG "%s: StartCfm success\n", cb->name);
        else
          printk(KERN_DEBUG "%s: StartCfm failed status %d\n",
                 cb->name, le16_to_cpu(cfm.Status));
      }

#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 4);
#endif
    }
    break;

  case ResyncConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_RESYNC_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      ResyncCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == ResyncConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_RESYNC_CFM)
        printk(KERN_DEBUG "%s: ResyncCfm  status %d\n",
               cb->name, le16_to_cpu(cfm.Status));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 2);
#endif
    }
    break;

  case SiteConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_SITE_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      SiteCfm_t cfm;
      int i;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == SiteConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_SITE_CFM) {
        printk(KERN_DEBUG "%s: SiteCfm  status %d ",
               cb->name, le16_to_cpu(cfm.Status));
        /* output too long ??? */
        for(i=0;i < sizeof(cfm.RSSI);i++) printk("%02x",cfm.RSSI[i]);
        printk("\n");
      }

#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        /* include the first 21 RSSI values */
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 10+15);
#endif
    }
    break;

  case SaveConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_SAVE_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      SaveCfm_t cfm;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == SaveConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_SAVE_CFM) 
        printk(KERN_DEBUG "%s: SaveCfm  status %d\n",
               cb->name, le16_to_cpu(cfm.Status));
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, &cfm.SignalID, 2);
#endif
    }
    break;

  case RFtestConfirm_ID:
    if ((cb->msg_from_dbg_mask & DBG_RFTEST_CFM) || 
        (cb->trace_mask & (1 << TRACE_MSG_RCV))) {
      RFtestCfm_t cfm;
      int i;
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == RFtestConfirm_ID);
      if (cb->msg_from_dbg_mask & DBG_RFTEST_CFM) {
        printk(KERN_DEBUG "%s: RFtestCfm ", cb->name);
        for(i=0;i < sizeof(cfm.unknown);i++) printk("%02x",cfm.unknown[i]);
        printk("\n");
      }
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, (uint8 *)&cfm.SignalID, 10);
#endif
    }
    break;

  default:
    /* dump first 32 byte (incl. signalID of unknown messages) */
    {
      uint8 buf[32];
      int i;
      Card_ESBQ_t esbq_cfm;

      copy_from_card(&buf, msgbuf+2, sizeof(buf), COPY_FAST, cb);
      copy_words_from_card((uint16 *)&esbq_cfm, cb->ESBQCfm, SZ_ESBQ_W, cb);
      printk(KERN_DEBUG "%s: ESBQ Cfm @ x%x: owner x%x buf x%x,"
             " unknown msg x%x from card @ x%x+2: ", 
             cb->name, cb->ESBQCfm, esbq_cfm.owner, esbq_cfm.buf, sigid, msgbuf);
      for(i=0;i<sizeof(buf);i++)
        printk("%02x",buf[i]);
      printk("\n");

      if (esbq_cfm.buf != msgbuf) {
        /* they should be equal ... */
        copy_from_card(&buf, esbq_cfm.buf, sizeof(buf), COPY_FAST, cb);
        printk(KERN_DEBUG "%s: esbq cfm.buf x%x: ", cb->name, esbq_cfm.buf);
        for(i=0;i<sizeof(buf);i++)
          printk("%02x",buf[i]);
        printk("\n");
      }
#if TRACE_NR_RECS > 0
      if (cb->trace_mask & (1 << TRACE_MSG_RCV))
        trace_add(cb, TRACE_MSG_RCV, buf, 10);
#endif
    }
  } /* switch (sigid) */

} /* end of debug_msg_from_card */
#endif //#ifndef DISABLE_DEBUG_RX_MSG

/* == PROC wl24n_rxint ==
   we got an interrupt from card:
   process all ESBQCfm's available and run the state machine. */
void wl24n_rxint(void *vcb)
{
  WL24Cb_t *cb = vcb;
  Card_Word_t msgbuf; /* points to message from card */
  uint8 sigid;  /* the msgid in msgbuf */
  int nr = 0;

#ifdef LOG_WL24N_RXINT
  printk(KERN_DEBUG "%s: %s\n", cb->name, __FUNCTION__);
#endif

  /* jal: nr++ < 10 just for testing !!! */
  while ((msgbuf=cfm_avail(cb)) != 0 && nr++ < 10) {

    /* let's see at the end of the while loop
       if any proc has restarted the card */
    cb->was_restarted = 0;

    /* all msg's to/from card start with
       struct { uint16 NextBlock; uint8 SignalID; ...
       -> +2 */
    copy_from_card(&sigid, msgbuf+2, 1, COPY_FAST, cb);

#ifndef DISABLE_DEBUG_RX_MSG
    debug_msg_from_card(cb, sigid, msgbuf);
#else
    /* if debug_msg_from_card is called we can trace more specific data
       inside it. Here we get only the id ... */
# if TRACE_NR_RECS > 0
    if (cb->trace_mask & (1 << TRACE_MSG_RCV)) 
      trace_add(TRACE_MSG_RCV, &sigid, 1);
# endif
#endif

    /* handle MIB get/set results here
       (maybe caused by ioctl's) */
    if (sigid == GetConfirm_ID || sigid == SetConfirm_ID) {
      copy_from_card(&cb->last_mibcfm, msgbuf,
                     sigid == SetConfirm_ID ? sizeof(SetCfm_t) :
                     sizeof(cb->last_mibcfm), COPY_FAST, cb);
      /* re-start the process waiting in the ioctl for completion
         of GetMib / SetMib - if there is any !*/
      cb->last_mibcfm_valid = 1;
      wake_up_interruptible(&cb->waitq); /* wake up the process sleeping on queue */
    } else 
      /* run state function */
      (*cb->state)(cb,sigid,msgbuf);

    /* don't call cfm_done if any state_proc decided to restart the card */
    if (!cb->was_restarted)
      cfm_done(cb);
  }

  free_requests(cb); /* free all processed ESBQ buffers and their tx buffers */

} /* wl24n_rxint */


/* == PROC wl24n_interrupt == */
void wl24n_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
  WL24Cb_t *cb = dev_id;

  /* even with this we get wrong irqs from the card resulting
     in alarms, unknown signals, ...
     I fear this bit is asserted too early - will try the CCSR
     of the cs instead (in wl24n_cs.c) */

  /* if (InB(cb->BaseAddr + NIC_GCR) & GCR_ECINT) */
    /* the MC2 is the interrupt source */

#ifdef RX_USE_TASK_QUEUE
  static struct tq_struct task;
  task.routine = wl24n_rxint;
  task.data = cb;
  queue_task(&task, &tq_immediate);
  mark_bh(IMMEDIATE_BH);
#else
  wl24n_rxint(cb);
#endif

  /* acknowledge Interrupt */
  OutB(InB(cb->BaseAddr + NIC_GCR) | GCR_ECINT, cb->BaseAddr + NIC_GCR);

}

/* == PROC state_invalid ==
   dummy state for nicer debugs */
void state_invalid(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{
  printk(KERN_WARNING "%s: state proc INVALID invoked\n",cb->name);
}

/* == PROC find_matching_bss == 
 find a matching BSS from cb->BSSset starting with index first_index.
 compares SSID and BSSType and returns new index or -1 if no BSS found */
/* Obey that the Belkin AP F5D6130 with unchecked "all SSID ANY" checkbox
   broadcasts a SSID of the correct length but filled with \0 - even if it's
   probed with the correct SSID ! */
int find_matching_bss(WL24Cb_t *cb, int first_index)
{
  int i;
  BSSDesc_t *bss;
#ifdef LOG_FIND_MATCHING_BSS
  printk(KERN_DEBUG "%s %s(..,%d)\n",cb->name, __FUNCTION__, first_index);
#endif

  for(i=first_index, bss = &cb->BSSset[i];
      i < NR_BSS_DESCRIPTIONS; i++, bss++) {
    if (bss->valid) { 

#ifdef LOG_FIND_MATCHING_BSS
      printk(KERN_DEBUG "%s %s: comparing %d. entry: cap %04x SSID "
             "(%d)%s (",
             cb->name, __FUNCTION__, i, bss->CapabilityInfo,
             bss->SSID[1], bss->SSID+2);
      dumpk(bss->SSID+2, bss->SSID[1]);
      printk(")\n");
#endif

      /* compare if BSSType and SSID match */
      if (!((cb->bsstype == BSSType_Infrastructure &&
             (bss->CapabilityInfo & CAP_ESS)) ||
            (cb->bsstype == BSSType_Independent &&
             (bss->CapabilityInfo & CAP_IBSS)) ||
            (cb->bsstype == BSSType_AnyBSS))) {

#ifdef LOG_FIND_MATCHING_BSS
        printk(KERN_DEBUG "%s %s: %d. entry skipped: bsstype %d cap %x \n",
               cb->name, __FUNCTION__, i,
               cb->bsstype, bss->CapabilityInfo);
#endif

        continue;
      }

      if (cb->match_wanted_bssid && 
          memcmp(cb->wanted_bssid, bss->BSSID, ETH_ALEN)) {
#ifdef LOG_FIND_MATCHING_BSS
        printk(KERN_DEBUG "%s %s: wanted BSSID "
               "%02X:%02X:%02X:%02X:%02X:%02X != "
               "%02X:%02X:%02X:%02X:%02X:%02X\n",
               cb->name, __FUNCTION__,
               cb->wanted_bssid[0],cb->wanted_bssid[1],cb->wanted_bssid[2],
               cb->wanted_bssid[3],cb->wanted_bssid[4],cb->wanted_bssid[5],
               bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
               bss->BSSID[3],bss->BSSID[4],bss->BSSID[5]);
#endif
        continue;
      }

      /* the BSS list may contain entries with an empty SSID
         (i.e. SSID[1] == 0) from an AP in "closed network" mode.
         Make sure that such an entry is never choosen !
         (We leave it in the list for displaying the environment) */
      if (bss->SSID[1] == 0 ||
          (cb->ESSID[1] != 0 &&
           (cb->ESSID[1] != bss->SSID[1] ||
            (memcmp(&cb->ESSID[2],&bss->SSID[2],cb->ESSID[1]) &&
             memcmp(&bss->SSID[2],zeros,bss->SSID[1]))))) {

        /* skip the entry if
           (the BSS' SSID is ANY) OR
           ((we look for an SSID != ANY) AND
           ((the length of our SSID differs from the entry's SSID) OR
           ((both SSID differ) AND (the SSID of the BSS is not filled with \0)))) */

#ifdef LOG_FIND_MATCHING_BSS
        printk(KERN_DEBUG "%s %s: %d. entry skipped: wanted ESSID (%d)%s ("
               cb->name, __FUNCTION__, i,  cb->ESSID[1],
               cb->ESSID+2);
        dumpk(cb->ESSID+2,cb->ESSID[1]);
        printk(") entry's SSID (%d)%s (", 
          bss->SSID[1], &bss->SSID[2]);
        dumpk(&bss->SSID[2],bss->SSID[1]);
        printk(")\n");
#endif

        continue;
      }

#ifdef LOG_FIND_MATCHING_BSS
      printk(KERN_DEBUG "%s %s: %d. entry choosen\n", cb->name, __FUNCTION__, i);
#endif
      return i;
    } // if (bss->valid) 
  } // for(...
  return -1;
}


/* == PROC add_bss_to_set == */
void add_bss_to_set(WL24Cb_t *cb, ScanCfm_t *cfm)
{
  int i, nr; /* nr is the index where we write 
                the BSS info from cfm into cb->BSSset */
  BSSDesc_t *bss;

#ifdef LOG_ADD_BSS_TO_SET
  printk(KERN_DEBUG "%s %s\n",cb->name, __FUNCTION__);
#endif

  /* nr stays -1 as long as we haven't found an entry to put the
     cfm info into */
  for(nr=-1, i=0, bss=cb->BSSset; nr == -1 && i < NR_BSS_DESCRIPTIONS;
      i++,bss++)
    if (!bss->valid) {
      nr = i;
    } else {
      if (memcmp(bss->BSSID,cfm->BSSID,sizeof(bss->BSSID)) == 0) {
        // we have the BSS already in the table
#ifdef LOG_ADD_BSS_TO_SET
        printk(KERN_DEBUG "%s %s: BSS already in %d. entry\n",
               cb->name, __FUNCTION__, nr);
#endif
        /* if the old entry has a non-empty SSID and the new one an empty
           do not overwrite, but skip this info */
        if (bss->SSID[1] != 0 && (cfm->SSID[1] == 0 || cfm->SSID[2] == 0)) {
#ifdef LOG_ADD_BSS_TO_SET
          printk(KERN_DEBUG "%s %s: skipped ScanCfm with empty SSID for BSSID "
                 "%02x:%02:%02x:%02x:%02:%02x with SSID (%d)%s (",
                 cb->name, __FUNCTION__,
                 bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
                 bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
                 bss->SSID[1], bss->SSID+2);
          dumpk(bss->SSID+2, bss->SSID[1]);
          printk(")\n");
#endif
          return;
        } else 
          /* (bss->SSID is empty OR cfm->SSID is not empty)
             --> overwrite the entry */
          nr = i;
      }
    } /* if (!bss->valid) ... else ... */
      
  if (nr != -1) {
    bss = &cb->BSSset[nr];
    bss->valid = TRUE;
    memcpy(bss->BSSID, cfm->BSSID, sizeof(bss->BSSID));
    memcpy(bss->SSID, cfm->SSID, sizeof(bss->SSID));
    bss->SSID[2+MIN(bss->SSID[1],sizeof(bss->SSID)-1-2)] = '\0'; // make it printable
    bss->BSSType = cfm->BSSType;
    bss->BeaconPeriod = le16_to_cpu(cfm->BeaconPeriod);
    bss->DTIMPeriod = le16_to_cpu(cfm->DTIMPeriod);
    memcpy(bss->Timestamp, cfm->Timestamp, sizeof(bss->Timestamp));
    memcpy(bss->LocalTime, cfm->LocalTime, sizeof(bss->LocalTime));
    memcpy(bss->PHYpset, cfm->PHYpset, sizeof(bss->PHYpset));
    memcpy(bss->CFpset, cfm->CFpset, sizeof(bss->CFpset));
    memcpy(bss->IBSSpset, cfm->IBSSpset, sizeof(bss->IBSSpset));
    bss->CapabilityInfo = le16_to_cpu(cfm->CapabilityInfo);
    memcpy(bss->BSSBasicRateSet, cfm->BSSBasicRateSet,
           sizeof(bss->BSSBasicRateSet));
    bss->ScanRSSI = cfm->RSSI;

#ifdef LOG_ADD_BSS_TO_SET
    printk(KERN_DEBUG "%s %s: added %d. entry: BSS SSID (%d)%s (",
           cb->name, __FUNCTION__, nr, bss->SSID[1], bss->SSID+2);
    dumpk(bss->SSID+2,bss->SSID[1]);
    printk(")\n");
#endif

    return;
  }

  printk(KERN_DEBUG "%s %s: BSSset full\n",cb->name, __FUNCTION__);
} /* end of add_bss_to_set */


/* == PROC try_join_next_bss ==
   try to join next BSS in BSSset. If no BSS is left there,
   either try to start an own IBSS (cb->BSSType != Infrastructure and
   many scan rounds tried) or scan again. If do_restart_if_empty is TRUE,
   this proc may restart the card.

   This proc is also called if authentication or association failed
   for any reason.
*/
void try_join_next_bss(WL24Cb_t *cb, int do_restart_if_empty)
{
  /* try to join next matching BSS from BSSset */
  cb->currBSS = find_matching_bss(cb,cb->currBSS+1);
  if (cb->currBSS >= 0) {
    /* we found a matching BSS - try to join it */

#if TRACE_NR_RECS > 0
    if (cb->trace_mask & (1 << TRACE_TRY_NEW_BSS)) {
      BSSDesc_t *bss = &cb->BSSset[cb->currBSS];
      uint8 buf[1+1+2+6+34];
      buf[0] = bss->PHYpset[2]; /* channel */
      buf[1] = bss->ScanRSSI;
      buf[2] = bss->CapabilityInfo >> 8;
      buf[3] = bss->CapabilityInfo & 0xff;
      memcpy(buf+4, bss->BSSID, 6);
      memcpy(buf+4+6, bss->SSID, SIZE_OF_SSID);
      trace_add(cb, TRACE_TRY_NEW_BSS, buf, 1+1+2+6+2+bss->SSID[1]);
    }
#endif

    newstate(cb, state_joining);
    JoinReq(cb, cb->currBSS);
  } else {
    if (do_restart_if_empty) {
      restart_card(cb);
    } else {
      /* no matching BSS or we tried all without success */
      cb->scan_runs++;
      cb->currBSS = -1;
      if (cb->bsstype == BSSType_Infrastructure ||
          cb->scan_runs < MAX_SCAN_RUNS_BEFORE_STARTING_IBSS) {
        int i;
        for(i=0; i < NR_BSS_DESCRIPTIONS; i++) {
          cb->BSSset[i].valid = FALSE;
          memset(cb->BSSset[i].SSID,0,sizeof(cb->BSSset[i].SSID));
        }
        newstate(cb,state_scanning);
        ScanReq(cb, SCAN_MIN_CHANNEL_TIME, SCAN_NEXT_RUN_MAX_CHANNEL_TIME,
                BSSType_AnyBSS, ScanType_Active);
      } else {
        /* start IBSS */
        newstate(cb,state_starting_ibss);
        StartReq(cb, cb->Channel, BSSType_Independent);
      }
    }
  }
} /* end of try_join_next_bss */


/* == PROC state_scanning ==
   we are scanning for BSS.
   For each BSS found we get a ScanConfirmID with Status == SUCCESS.
   The last msg is Status == TIMEOUT. */
void state_scanning(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{
  switch(sigid) {

    /* we may still get some MdConfirm_ID from former tx data */
  case MdConfirm_ID:
    {
      MdConfirm_t cfm;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == MdConfirm_ID);

      free_txbuf(cb,cfm.Data);
    }
    break;

  case ScanConfirm_ID:
    {
      ScanCfm_t cfm;
      uint16 status;
      
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == ScanConfirm_ID);
      status = le16_to_cpu(cfm.Status);

      if (status == Status_Success) {

#if TRACE_NR_RECS > 0
        if (cb->trace_mask & (1 << TRACE_NEW_BSS_FOUND)) {
          uint8 buf[1+1+2+6+34];
          buf[0] = cfm.PHYpset[2]; /* channel */
          buf[1] = cfm.RSSI;
          buf[2] = cfm.CapabilityInfo >> 8;
          buf[3] = cfm.CapabilityInfo & 0xff;
          memcpy(buf+4, cfm.BSSID, 6);
          memcpy(buf+4+6, cfm.SSID, SIZE_OF_SSID);
          trace_add(cb, TRACE_NEW_BSS_FOUND, buf, 1+1+2+6+2+cfm.SSID[1]);
        }
#endif
  
        /* add BSS to list */
        add_bss_to_set(cb,&cfm);

      } else if (status == Status_Timeout) {
        /* try to join a matching BSS from BSSset */
        try_join_next_bss(cb, FALSE);
      } else {
        printk( KERN_WARNING "%s: ScanCfm unknown status x%x\n",cb->name,
                status);
        try_join_next_bss(cb, FALSE);
      }
    }
    break;

  default:
    printk(KERN_WARNING "%s: state SCANNING: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */
} /* end of state_scanning */


/* == PROC state_joining ==
   we have issued a JoinReq for cb->BSSset[cb->currBSS] */
void state_joining(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{

  switch(sigid) {

    /* we may still get some MdConfirm_ID from former tx data */
  case MdConfirm_ID:
    {
      MdConfirm_t cfm;
  
      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == MdConfirm_ID);

      free_txbuf(cb,cfm.Data);
    }
    break;

  case JoinConfirm_ID:
    {
      JoinCfm_t cfm;
      uint16 status;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == JoinConfirm_ID);
      status = le16_to_cpu(cfm.Status);

      if (status == Status_Success) {
        if (cb->BSSset[cb->currBSS].CapabilityInfo & CAP_ESS) {
          newstate(cb,state_auth);
          AuthReq(cb, AuthType_OpenSystem, AUTH_TIMEOUT,
                  cb->BSSset[cb->currBSS].BSSID);
        } else {
          BSSDesc_t *bss = &cb->BSSset[cb->currBSS];
          /* we successfully joined an IBSS */
          assert(bss->CapabilityInfo & CAP_IBSS);
          printk(KERN_NOTICE "%s: connected to IBSS chan %d BSSID "
                 "%02X:%02X:%02X:%02X:%02X:%02X SSID (%d)%s\n",
                 cb->name, bss->PHYpset[2],
                 bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
                 bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
                 bss->SSID[1], bss->SSID+2);

# ifdef WIRELESS_EXT
          /* we start with the Scan RSSI until we get the first MdInd,
             which may take a while */
          cb->wstats.qual.level = bss->ScanRSSI;
# endif

          newstate(cb,state_joined_ibss);
          /* jal: at first time, we should call netif_start_queue !!! */

          netif_carrier_on(cb->netdev); /* we got a carrier */
          netif_wake_queue(cb->netdev);
        }
      } else {
        /* JoinReq failed */
        /* try to join next matching BSS from BSSset */
        try_join_next_bss(cb, FALSE);
      }
    }
    break;

  default:
    printk(KERN_WARNING "%s: state JOINING: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */

} /* end of state_joining */                


/* == PROC state_auth ==
   we sent an AuthReq to the BSS and wait for answer */
void state_auth(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{
  switch(sigid) {

  case AuthConfirm_ID:
    {
      AuthCfm_t cfm;
      uint16 status, authtype;
      BSSDesc_t *bss = &cb->BSSset[cb->currBSS];

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == AuthConfirm_ID);
      status = le16_to_cpu(cfm.Status);
      authtype = le16_to_cpu(cfm.Type);

      if (!memcmp(bss->BSSID, cfm.MacAddress, sizeof(cfm.MacAddress))) {
        printk(KERN_WARNING "%s: expected AuthCfm from "
               "%02X:%02X:%02X:%02X:%02X:%02X got it from "
               "%02X:%02X:%02X:%02X:%02X:%02X\n",
               cb->name,
               bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
               bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
               cfm.MacAddress[0],cfm.MacAddress[1],cfm.MacAddress[2],
               cfm.MacAddress[3],cfm.MacAddress[4],cfm.MacAddress[5]);
        return;
      }

      if (authtype != AuthType_OpenSystem)
        printk(KERN_DEBUG "%s: AuthCfm received with Auth type %d\n",
               cb->name, authtype);
      /* continue */

      if (status == Status_Success) {
        if (cb->dbg_mask & DBG_AUTH_BSS) {
          printk(KERN_DEBUG "%s: authenticated to BSSID"
                 " %02X:%02X:%02X:%02X:%02X:%02X SSID (%d)%s (",
                 cb->name,
                 bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
                 bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
                 bss->SSID[1], bss->SSID+2);
          dumpk(bss->SSID+2, bss->SSID[1]);
          printk(")\n");
        }
        AssocReq(cb);
        newstate(cb, state_assoc);

      } else {

        printk(KERN_DEBUG "%s: AuthReq failed to BSSID "
               "%02X:%02X:%02X:%02X:%02X:%02X "
               "(status %d) chan %d SSID (%d)%s (",
               cb->name,
               bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
               bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
               status, bss->PHYpset[2], bss->SSID[1], bss->SSID+2);
        dumpk(bss->SSID+2, bss->SSID[1]);
        printk(")\n");

        try_join_next_bss(cb, FALSE);
      }
    }
    break;

  default:
    printk(KERN_WARNING "%s: state AUTH: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */
} /* end of state_auth */

/* == PROC state_assoc ==
   we sent an AssocReq to the BSS and wait for answer */
void state_assoc(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{
  switch(sigid) {
  case AssocConfirm_ID:
    {
      AssocCfm_t cfm;
      uint16 status;
      BSSDesc_t *bss = &cb->BSSset[cb->currBSS];

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == AssocConfirm_ID);
      status = le16_to_cpu(cfm.Status);

      if (status == Status_Success) {
        if (cb->dbg_mask & DBG_CONNECTED_BSS) {
          printk(KERN_DEBUG "%s: Assoc succeeded to ESS chan %d BSSID"
                 " %02X:%02X:%02X:%02X:%02X:%02X SSID (%d)%s (",
                 cb->name, bss->PHYpset[2],
                 bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
                 bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
                 bss->SSID[1], bss->SSID+2);
          dumpk(bss->SSID+2, bss->SSID[1]);
          printk(")\n");
        }

# ifdef WIRELESS_EXT
        /* we start with the Scan RSSI until we get the first MdInd,
           which may take a while */
        cb->wstats.qual.level = bss->ScanRSSI;
# endif

        printk(KERN_NOTICE "%s: connected to ESS chan %d BSSID"
               " %02X:%02X:%02X:%02X:%02X:%02X SSID (%d)%s\n",
               cb->name, bss->PHYpset[2],
               bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
               bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
               bss->SSID[1], bss->SSID+2);

        newstate(cb, state_joined_ess);
        netif_carrier_on(cb->netdev); /* we got a carrier */
        /* jal: at first time, we should call netif_start_queue !!! */
        netif_wake_queue(cb->netdev);

      } else {

        printk(KERN_DEBUG "%s: AssocReq failed with status %d to chan %d "
               "BSSID %02X:%02X:%02X:%02X:%02X:%02X SSID (%d)%s (",
               cb->name, status, bss->PHYpset[2],
               bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
               bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
               bss->SSID[1], bss->SSID+2);
        dumpk(bss->SSID+2, bss->SSID[1]);
        printk(")\n");

        try_join_next_bss(cb, FALSE);
      }
    }
    break;

  case DeauthIndicate_ID:
    {
      DeauthInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == DeauthIndicate_ID);

      printk(KERN_DEBUG "%s: DeauthInd reason %d from "
             "%02X:%02X:%02X:%02X:%02X:%02X\n",
             cb->name, le16_to_cpu(ind.Reason),
             ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
             ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);

      /* try to join the next BSS iff the DeauthInd came from the
         BSS we currently try to associate with */
      if (!memcmp(ind.MacAddress,cb->BSSset[cb->currBSS].BSSID,
                  sizeof(cb->BSSset[cb->currBSS].BSSID)))
        try_join_next_bss(cb, FALSE);
      else {
        /* TODO: mark BSS as non-assoc with in our table */
      }
    }
    break;

  default:
    printk(KERN_WARNING "%s: state ASSOC: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */
} /* end of state_assoc */

/* == PROC handle_mdcfm == 
 handle MdConfirm_ID from the card */
void handle_mdcfm(WL24Cb_t *cb, Card_Word_t msgbuf, int do_leaky_bucket)
{

  MdConfirm_t cfm;
  uint16 status;

  copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
  assert(cfm.SignalID == MdConfirm_ID);
  status = le16_to_cpu(cfm.Status);

  /* free tx buffer in every case */
  free_txbuf(cb,cfm.Data);

  /* if we had to stop it before, wake it up */
  netif_wake_queue(cb->netdev);

  if (status != StatusMdCfm_Success) {
    if (status == StatusMdCfm_Fail) {
      /* in some locations in ap mode we see a lot of these Fail
         while the packets still go through to the AP ... ?
         -> we count them only */
      cb->stats.tx_dropped++;
    } else {

      cb->stats.tx_errors++;
      /* fail status, but not MdCfm_Fail */
# ifdef WIRELESS_EXT
      if (status == StatusMdCfm_NoBSS)
        cb->wstats.miss.beacon++;
      else
        cb->wstats.discard.misc++;
# endif

      if (do_leaky_bucket) {
        if ((cb->mdcfm_failure += MDCFM_FAIL_PENALTY) > MDCFM_RESCAN_THRE) {
          printk(KERN_NOTICE "%s: %s: too many failed MdConfirm"
                 " (last status x%x) -> join next BSS/restart\n",
                 cb->name, __FUNCTION__, status);
          netif_carrier_off(cb->netdev); /* we lost our carrier */
          netif_stop_queue(cb->netdev);    /* stop net if */

          cb->mdcfm_failure = 0;
          /* look into the BSS table if there is another BSS of
             the same networkname,
             and try to join it first before we restart */
          try_join_next_bss(cb,TRUE); /* try to join next matching BSS */
        }
      }
    }
  } else {
    /* status == Status_Success, data were successfully transmitted,
       get the length from cb->txbuf_len_list and update statistics */
    int nr = (cfm.Data - cb->FreeTxBufStart) / sizeof(Card_TxBuf_t);
    if (nr >= 0 && nr < cb->txbuf_len_list_len) {
      if (cb->txbuf_len_list[nr] > sizeof(TxHeader_t))
        cb->stats.tx_bytes += cb->txbuf_len_list[nr] - 
          sizeof(TxHeader_t);
      cb->txbuf_len_list[nr] = 0;
    }
    cb->stats.tx_packets++;
    
    if (do_leaky_bucket) {
      if (cb->mdcfm_failure > 0) {
        cb->mdcfm_failure -= MDCFM_OK_VALUE;
        if (cb->mdcfm_failure < 0)
          cb->mdcfm_failure = 0;
      }
    }
  }
} /* handle_mdcfm */

/* == PROC wl24n_check_frags ==
   check for rx fragments:
     - if this is the last fragment of a chain, this will copy the whole chain
       into cb->databuffer and update databuffer.length accordingly, returns 1
     - if this is not a fragment of a chain, databuffer remains unchanged,
       returns 1
     - if this is a fragment and more will follow, the fragment is stored
       and zero returned
     - if this is a retry packet we have already received, zero is returned
*/
int wl24n_check_frags(WL24Cb_t *cb, databuffer_t *dbuf)
{
  /* offsets of address2 and sequence control field in dbuf+offset */
#define OFFSET_ADDR2 \
(offsetof(RxHeader_t,Address2)-offsetof(RxHeader_t,FrameControl))
#define OFFSET_SEQCTL \
(offsetof(RxHeader_t,Sequence)-offsetof(RxHeader_t,FrameControl))
#define HDR_LENGTH \
(2+offsetof(RxHeader_t,Sequence)-offsetof(RxHeader_t,FrameControl))

  int i;
  uint8 *hdr = dbuf->buffer + dbuf->offset;
  uint8 *addr2 = hdr + OFFSET_ADDR2; /* address2 field */
  /* sequence control */
  int seqctrl = hdr[OFFSET_SEQCTL] | (hdr[OFFSET_SEQCTL+1]<<8);
  int seq_nr = seqctrl >> 4;
  int frag_nr = seqctrl & 0xf; 
  uint16 frmctl_high = hdr[1]; /* frame control field, high byte */
  RxFragCache_t *cline;

  assert(dbuf->length >= HDR_LENGTH);
  if (dbuf->length < HDR_LENGTH)
    return 0; /* no more processing in caller */

  /* look for address 2 */
  for(i=0, cline = cb->rx_cache; i < NR_RX_FRAG_CACHES; i++, cline++) {
    if (cline->in_use && !memcmp(cline->addr2, addr2, ETH_ALEN))
      break;
  }

  /* shortcut for non-fragmented packets - I hope the fragment number
     never wraps ! */
  if (i == NR_RX_FRAG_CACHES && frag_nr == 0 && 
      (frmctl_high & MOREFRAGBIT) == 0)
    return 1;

  if (i < NR_RX_FRAG_CACHES) {
    /* we found an entry for address2 from new data packet in cline */

    if ((cb->dbg_mask & DBG_MSG_FROM_CARD) &&
        (cb->msg_from_dbg_mask & DBG_RX_FRAGMENTS)) {
      printk(KERN_DEBUG "%s: rx frag (seqnr x%x fragnr x%x "
             "frmctl x%xxx len x%x) matched addr2 in cache "
             "line %d (seqnr x%x fragnr x%x len x%x)\n",
             cb->name, seq_nr, frag_nr, frmctl_high, dbuf->length,
             i, cline->seq_nr, cline->frag_nr, cline->buf_len);
    }

    if (seq_nr == cline->seq_nr) {
      /* same sequence number */
      if (frag_nr == (cline->frag_nr+1)) {
        /* next fragment */
        if ((dbuf->length-HDR_LENGTH) <=
            (sizeof(cline->buf)-cline->buf_len)) {
          /* the new data fit into the buffer in cline */
          memcpy(cline->buf+cline->buf_len, hdr+HDR_LENGTH,
                 dbuf->length-HDR_LENGTH);
          cline->buf_len += (dbuf->length-HDR_LENGTH);
          cline->frag_nr++;
          cline->last_update = jiffies;

#ifdef LOG_RX_FRAGMENTS
          printk(KERN_DEBUG "%s: rx frag (len x%x) added to cline %d\n",
                 cb->name, dbuf->length, i);
#endif
          if (frmctl_high & MOREFRAGBIT) {
            /* some fragments follow */
            return 0; /* consumed data here */
          } else {
            /* this was the last fragment */
            /* we re-use the header in dbuf->buffer+dbuf->offset
               and attach the complete payload */
            cline->in_use = 0;
            if ((sizeof(dbuf->buffer)-dbuf->offset) >=
                HDR_LENGTH+cline->buf_len) {
              memcpy(hdr+HDR_LENGTH, cline->buf, cline->buf_len);
              dbuf->length = HDR_LENGTH+cline->buf_len;
              return 1;
            } else {
              /* dbuf->buffer was too small */
              cb->wstats.discard.fragment++;
#ifdef LOG_RX_FRAGMENTS
              printk(KERN_DEBUG "%s: rx frag buf too large (x%x > x%x-x%x-x%x)\n",
                     cb->name, cline->buf_len, sizeof(dbuf->buffer),dbuf->offset,
                     HDR_LENGTH);
#endif
              return 0;
            }
          }
        } else {
          /* new fragment's payload did not fit into cline->buf */
#ifdef LOG_RX_FRAGMENTS
            printk(KERN_DEBUG "%s: rx frag (len x%x) too large " 
                   "(only x%x bytes left in cline %d)\n",
                   cb->name, dbuf->length,
                   sizeof(cline->buf) - cline->buf_len, i);
#endif
            /* cline->buf overflow */
            cline->in_use = 0;
            cb->wstats.discard.fragment++;
            return 0;

        }
      } else {
        /* fragment number in new fragment is incorrect */
        if (cline->frag_nr != frag_nr) {
          /* we lost a fragment ... */
#ifdef LOG_RX_FRAGMENTS
          printk(KERN_DEBUG "%s: rx frag: got frag_nr x%x, expected x%x\n",
                 cb->name, frag_nr, cline->frag_nr+1);
#endif
          cline->in_use = 0;
          cb->wstats.discard.fragment++;
        } else {
#ifdef LOG_RX_FRAGMENTS
          printk(KERN_DEBUG "%s: rx frag ignored re-sent fragment\n",
                 cb->name);
#endif
        }
        return 0;
      }
    } else {
      /* we got another sequence number */
#ifdef LOG_RX_FRAGMENTS
      printk(KERN_DEBUG "%s: rx frag: new seq_nr x%x (old x%x)\n",
             cb->name, seq_nr, cline->seq_nr);
#endif
      cb->wstats.discard.fragment++; /* we lost a data packet */
      if (frag_nr == 0) { 
        /* it is the first fragment */
        if ((frmctl_high & MOREFRAGBIT)) {
          /* more will follow -> re-use cline entry for new data */
          assert(sizeof(cline->buf) > (dbuf->length-HDR_LENGTH));
          cline->buf_len = dbuf->length-HDR_LENGTH;
          memcpy(cline->buf,hdr+HDR_LENGTH,cline->buf_len);
          cline->seq_nr = seq_nr;
          cline->frag_nr = 0;
          cline->last_update = jiffies;
#ifdef LOG_RX_FRAGMENTS
          printk(KERN_DEBUG "%s: rx frag: re-init cline %d\n",
                 cb->name, i);
#endif
          return 0; /* consumed data */
        } else {
          /* unfragmented rx */
          cline->in_use = 0;
          return 1; /* give data unchanged back */
        }
      } else {
        /* another sequence number and not the first fragment */
#ifdef LOG_RX_FRAGMENTS
        printk(KERN_DEBUG "%s: rx frag: another seq_nr, not first frag "
               "- skipped\n",
               cb->name);
#endif
        cline->in_use = 0;
        cb->wstats.discard.fragment++; /* we lost a data packet */
        return 0;
      }
    }
  } else {
#ifdef LOG_RX_FRAGMENTS
        printk(KERN_DEBUG "%s: rx frag: new addr2 "
               "%02X:%02X:%02X:%02X:%02X:%02X "
               "seq_nr x%x frag_nr x%x netlen x%x\n",
               cb->name,
               addr2[0],addr2[1],addr2[2],
               addr2[3],addr2[4],addr2[5], seq_nr, frag_nr,
               dbuf->length - HDR_LENGTH);
#endif

    /* we found no match for addr2 in cache */
    if (frag_nr != 0) {
      cb->wstats.discard.fragment++; /* we lost a data packet */
      return 0;
    } else {
      assert(frmctl_high & MOREFRAGBIT);
      if (frmctl_high & MOREFRAGBIT) {
        /* we must store this fragment */
        /* look for an empty entry and for the oldest updated */
        int oldest = 0;
        for(i=0, cline = cb->rx_cache; i < NR_RX_FRAG_CACHES; i++, cline++) {
          if (!cline->in_use)
            break;
          if (cline->last_update < cb->rx_cache[oldest].last_update)
            oldest = i;
        }
        if (i == NR_RX_FRAG_CACHES) {
          /* no empty entry found, remove the oldest one */
          cline = &cb->rx_cache[oldest];
          i = oldest;
          cb->wstats.discard.fragment++;
#ifdef LOG_RX_FRAGMENTS
          printk(KERN_DEBUG "%s: rx frag: overwrite oldest cline "
                 "addr2 %02X:%02X:%02X:%02X:%02X:%02X "
                 "seq_nr x%x frag_nr x%x buf_len x%x jiffies %u\n",
                 cb->name,
                 cline->addr2[0],cline->addr2[1],cline->addr2[2],
                 cline->addr2[3],cline->addr2[4],cline->addr2[5],
                 cline->seq_nr, cline->frag_nr, cline->buf_len,
                 cline->last_update);
#endif
        }
        
        /* fill cline */
        assert((dbuf->length - HDR_LENGTH) <= sizeof(cline->buf));
        cline->in_use = 1;
        memcpy(cline->addr2,addr2,ETH_ALEN);
        cline->seq_nr = seq_nr;
        cline->frag_nr = frag_nr;
        cline->buf_len = dbuf->length - HDR_LENGTH;
        memcpy(cline->buf,hdr+HDR_LENGTH,dbuf->length-HDR_LENGTH);
        cline->last_update = jiffies;

#ifdef LOG_RX_FRAGMENTS
          printk(KERN_DEBUG "%s: rx frag: fill cline %d with "
                 "addr2 %02X:%02X:%02X:%02X:%02X:%02X "
                 "seq_nr x%x frag_nr x%x buf_len x%x jiffies %u\n",
                 cb->name, i,
                 cline->addr2[0],cline->addr2[1],cline->addr2[2],
                 cline->addr2[3],cline->addr2[4],cline->addr2[5],
                 cline->seq_nr, cline->frag_nr,cline->buf_len,
                 cline->last_update);
#endif

        return 0;
      } else {
        /* frag_nr = 0 and no more frags -> unfragmented packet */
        return 1;
      }
    }
  }
} /* wl24n_check_frags */

/* == PROC handle_mdind == */
void handle_mdind(WL24Cb_t *cb, Card_Word_t msgbuf)
{
  MdInd_t ind;
  RxHeader_t hdr;
  struct  sk_buff *skb;

  int32 RestLen, ThisLen;
  char *pBuffer;
  uint16 ptr;

  copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
  assert(ind.SignalID == MdIndicate_ID);

  /* get the rx header */
  copy_from_card(&hdr, ind.Data, sizeof(hdr), COPY_FAST, cb);

  /* copy the whole frame to the WEP buffer */
  /* start copying at the FrameControl field in RxHeader_t */

  RestLen = cb->databuffer.length = ind.Size - 4;
  pBuffer = cb->databuffer.buffer;
  cb->databuffer.offset = 0;
  ThisLen = min(RestLen, 210 + 24);
  copy_from_card(pBuffer, ind.Data + offsetof(RxHeader_t,FrameControl),
                 ThisLen, COPY_FAST, cb);
  pBuffer += ThisLen; RestLen -= ThisLen;
  copy_words_from_card(&ptr, ind.Data + 2, 1, cb);
  while (RestLen)
    {
      ThisLen = min(RestLen, 251);
      copy_from_card(pBuffer, ptr + 5, ThisLen, COPY_FAST, cb);
      pBuffer += ThisLen; RestLen -= ThisLen;
      copy_words_from_card(&ptr, ptr + 2, 1, cb);
    }
  
  /* decrypt frame ? */

  if (cb->databuffer.buffer[cb->databuffer.offset + 1] & WEPBIT)
    {
      if (wl24decrypt(&cb->databuffer, &cb->wepstate))
        {
          cb->wstats.discard.code++;
          return;
        }
    }
  /* otherwise discard frame if in restricted mode */
  else if (cb->wepstate.exclude_unencr)
    {
      printk(KERN_DEBUG "%s: received unencrypted frame in restricted mode,"
             " source addr %02X:%02X:%02X:%02X:%02X:%02X\n",
             cb->name,
             hdr.Address2[0],hdr.Address2[1],hdr.Address2[2],
             hdr.Address2[3],hdr.Address2[4],hdr.Address2[5]);
      cb->wstats.discard.misc++;
      return;
    }

#if IW_MAX_SPY > 0
  {
    int i;
    for(i=0; i < cb->iwspy_number; i++)
      if (!memcmp(cb->iwspy[i].spy_address,
                  cb->databuffer.buffer + cb->databuffer.offset + 6, ETH_ALEN)) {
        cb->iwspy[i].spy_level = hdr.RSSI;
        cb->iwspy[i].updated = 1;
        break;
      }
  }
#endif

  if (cb->state == state_joined_ibss || cb->state == state_joined_ess) {
    /* if we have joined an IBSS or ESS
       store the RSSI in the BSSset table */
    assert(cb->currBSS >= 0 && cb->currBSS < NR_BSS_DESCRIPTIONS);
    assert(cb->BSSset[cb->currBSS].valid);
    cb->BSSset[cb->currBSS].MdIndRSSI = hdr.RSSI;
  }

# ifdef WIRELESS_EXT
  cb->wstats.qual.level = hdr.RSSI;
# endif

  /* check for rx fragments:
     - if this is the last fragment of a chain, this will copy the whole chain
       into cb->databuffer and update databuffer.length accordingly, returns 1
     - if this is not a fragment of a chain, databuffer remains unchanged, returns 1
     - if this is a fragment and more will follow, the fragment is stored and zero returned
     - if this is a retry packet we have already received, zero is returned
  */
  if (!wl24n_check_frags(cb, &cb->databuffer))
    return;

  /* convert to 802.3 */

  if (wl24unpack(&cb->databuffer, cb->llctype))
    {
      cb->wstats.discard.misc++;
      return;
    }

  if (cb->databuffer.length <= 14) {
    /* no payload (the ELSA IL-2 sends every second an empty packet to check
       if their internal PCMCIA card still works) */
#ifdef LOG_MDIND_NO_PAYLOAD
    printk(KERN_DEBUG "%s %s: empty MdInd LLCType %d BufLen %x\n",
           cb->name, __FUNCTION__, cb->llctype, BufLen); 
#endif
    return;
  }

#ifdef LOG_STATE_IBSS_MDIND
  printk(KERN_DEBUG "%s %s: MdInd LLCType %d ind.Size %x BufLen",
         cb->name, __FUNCTION__, cb->llctype, ind.Size, BufLen); 
#endif

#ifdef DEBUG_DONT_PROCESS_MDIND
  break;
#endif

  skb = dev_alloc_skb(cb->databuffer.length + 2); /* +2 for max. aligment below */
  if (skb == NULL) {
    printk("%s: Cannot allocate a sk_buff of size %d\n",
           cb->name, cb->databuffer.length + 2);
    cb->stats.rx_dropped++;
    return;
  }

  skb->dev = cb->netdev;
  skb_reserve(skb, 2);
  /* IP headers on 16 bytes boundaries, except for Ether802_3, which
     has 6+6+2+3=17 byte header before IP start (all other have
     6+6+2 bytes), but Ether802_3 is no IP, but a Novell Frame Type */

  cb->stats.rx_bytes += cb->databuffer.length;
  cb->stats.rx_packets++;
  cb->netdev->last_rx = jiffies;

  /* copy resulting buffer to SKB */

  wl24drain(&cb->databuffer, skb_put(skb, cb->databuffer.length));

#ifdef LOG_STATE_IBSS_MDIND
  printk(KERN_DEBUG "%s %s: skb->data: ", cb->name, __FUNCTION__);
  dumpk(skb->data, 12);
  printk("\n");
#endif      

  /* Notify the upper protocol layers that there is another packet */
  /* to handle. netif_rx() always succeeds. see dev.c for more.    */
  skb->protocol = eth_type_trans(skb, cb->netdev);
  netif_rx(skb);
} /* handle_mdind */


/* == PROC state_starting_ibss ==
   we tried to setup an IBSS (via StartReq) on cb->Channel */
void state_starting_ibss(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{

  switch(sigid) {
  case StartConfirm_ID:
    {
      StartCfm_t cfm;
      uint16 status;

      copy_from_card(&cfm, msgbuf, sizeof(cfm), COPY_FAST, cb);
      assert(cfm.SignalID == StartConfirm_ID);
      status = le16_to_cpu(cfm.Status);

      if (status == Status_Success) {
        if (cb->dbg_mask & DBG_CONNECTED_BSS)
          printk(KERN_DEBUG "%s: started own IBSS on channel %d\n",
                 cb->name, cb->Channel);
        newstate(cb, state_started_ibss);
        netif_carrier_on(cb->netdev); /* we got a carrier */
        netif_wake_queue(cb->netdev);
      } else {
        int i;

        printk(KERN_DEBUG "%s: starting own IBSS on channel %d failed"
               "(status %d)\n", cb->name, cb->Channel, status);

        /* fall back into scanning */
        cb->scan_runs = 0;
        for(i=0; i < NR_BSS_DESCRIPTIONS; i++) {
          cb->BSSset[i].valid = FALSE;
          memset(cb->BSSset[i].SSID,0,sizeof(cb->BSSset[i].SSID));
        }
        cb->currBSS = -1;
        ScanReq(cb, SCAN_MIN_CHANNEL_TIME, SCAN_FIRST_RUN_MAX_CHANNEL_TIME,
                BSSType_AnyBSS, ScanType_Active);
        newstate(cb,state_scanning);
      }
    }
    break;

  default:
    printk(KERN_WARNING "%s: state STARTING_IBSS: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */

} /* end of state_starting_ibss */                


/* == PROC state_joined_ibss ==
      we joined an IBSS  */
/* how do we recognize if we have left the area of the IBSS ?
   -> we'll get an Alarm from the card (do we really ???) */
void state_joined_ibss(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{

  switch(sigid) {
  case MdConfirm_ID:
    handle_mdcfm(cb, msgbuf, TRUE); /* TRUE -> update leaky bucket counter */
    break;

  case MdIndicate_ID:
    handle_mdind(cb,msgbuf);
    break;

  default:
    printk(KERN_WARNING "%s: state JOINED_IBSS: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */
} /* end of state_joined_ibss */


/* == PROC state_started_ibss ==
      we have started our own IBSS */
/* how do we recognize if we have left the area of the IBSS ?
   -> we'll get an Alarm from the card (do we really ???) */
void state_started_ibss(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{

  switch(sigid) {
  case MdConfirm_ID:
    handle_mdcfm(cb, msgbuf, FALSE); /* FALSE -> don't update leaky bucket counter */
    break;

  case MdIndicate_ID:
    handle_mdind(cb,msgbuf);
    break;

  default:
    printk(KERN_WARNING "%s: state STARTED_IBSS: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */
} /* end of state_started_ibss */


/* == PROC state_joined_ess ==
   we joined an ESS */
void state_joined_ess(WL24Cb_t *cb, uint8 sigid, Card_Word_t msgbuf)
{

  assert(cb->bsstype == BSSType_Infrastructure ||
         cb->bsstype == BSSType_AnyBSS);

  switch(sigid) {

  case MdConfirm_ID:
    handle_mdcfm(cb, msgbuf, TRUE); /* TRUE -> update leaky bucket counter */
    break;

  case MdIndicate_ID:
    handle_mdind(cb, msgbuf);
    break;

    /* original sw on DeauthInd / DisassocInd / Alarm:
       - send ResyncReq
       - on rx of ResyncCfm (either successful or unsuccessful)
       try to join a BSS from list, starting with the 
       current one (!) 
       What does ResyncReq trigger ??? */

  case DeauthIndicate_ID:
    {
      DeauthInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == DeauthIndicate_ID);

      printk(KERN_DEBUG "%s: DeauthInd reason %d from "
             "%02X:%02X:%02X:%02X:%02X:%02X\n",
             cb->name, le16_to_cpu(ind.Reason),
             ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
             ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);

      /* try to join the next BSS iff the DeauthInd came from the
         BSS we are currently associated with */
      if (!memcmp(ind.MacAddress,cb->BSSset[cb->currBSS].BSSID,
                  sizeof(cb->BSSset[cb->currBSS].BSSID))) {
        /* stop net if */
        netif_carrier_off(cb->netdev); /* we have no carrier anymore */
        netif_stop_queue(cb->netdev);
        /* look for next bss */
        try_join_next_bss(cb, FALSE);
      } else {
        /* TODO: mark BSS as non-auth-with and non-assoc-with
           (does DeauthInd imply DisassocInd ???)
           in our table */
      }
    }
    break;

  case DisassocIndicate_ID:
    {
      DisassocInd_t ind;

      copy_from_card(&ind, msgbuf, sizeof(ind), COPY_FAST, cb);
      assert(ind.SignalID == DisassocIndicate_ID);

      printk(KERN_DEBUG "%s: DisassocInd reason %d from "
             "%02X:%02X:%02X:%02X:%02X:%02X\n",
             cb->name, le16_to_cpu(ind.Reason),
             ind.MacAddress[0],ind.MacAddress[1],ind.MacAddress[2],
             ind.MacAddress[3],ind.MacAddress[4],ind.MacAddress[5]);

      /* try to join the next BSS iff the DisassocInd came from the
         BSS we are currently associated with */
      if (!memcmp(ind.MacAddress,cb->BSSset[cb->currBSS].BSSID,
                  sizeof(cb->BSSset[cb->currBSS].BSSID))) {
        /* stop net if */
        netif_carrier_off(cb->netdev); /* we have no carrier anymore */
        netif_stop_queue(cb->netdev);
        /* TODO: try to assoc with another already authenticated-to
           BSS - something like:

           if (!try_assoc_to_next_auth_bss(cb))
           try_join_next_bss(cb, FALSE); */

        /* look for next bss */
        try_join_next_bss(cb, FALSE);
      } else {
        /* TODO: mark BSS as non-assoc-with with in our table */
      }
    }
    break;

  case Alarm_ID: /* we lost the beacon from the current STA */

    netif_carrier_off(cb->netdev); /* we have no carrier anymore */
    netif_stop_queue(cb->netdev);    /* stop net if */
    try_join_next_bss(cb, FALSE); /* try to join next matching BSS */
    break;

    /* TODO: When do we send DeassocReq / DeauthReq ourselves, i.e.
       implement roaming in the ESS ... */

  default:
    printk(KERN_WARNING "%s: state JOINED_ESS: got unexpected signal %d\n",
           cb->name, sigid);
  } /* switch(sigid) */

} /* end of state_joined_ess */


/* == PROC proc_read_param == */
int proc_read_param(char *buf, char **start, off_t offset, int count, 
                    int *eof, void *data)
{
  WL24Cb_t *cb = data;
  char *p = buf;
  int i;
  char obuf[32];

#define CHECK_ENDE if ((p-buf) > (count - 80)) goto proc_read_param_ende

  p += sprintf(p,
               "LLCType:     %s (%d)\n"
               "networktype: %s (%d)\n",
               cb->llctype == LLCType_WaveLan ? "LLCType_WaveLan" :
               "LLCType_IEEE_802_11", cb->llctype,
               cb->bsstype == BSSType_Infrastructure ? "BSSType_Infrastructure" : 
               cb->bsstype == BSSType_Independent ? "BSSType_Independent" :
               "BSSType_AnyBSS", cb->bsstype);
  CHECK_ENDE;

  p += sprintf(p,
               "Channel:     %d\n"
               "networkname: \"%s\" (", cb->Channel, cb->ESSID+2);
  CHECK_ENDE;

  for(i=0; i < cb->ESSID[1] + 2; i++) {
    p+= sprintf(p, "%02x ", cb->ESSID[i]);
    CHECK_ENDE;
  }
  p += sprintf(p,")\n");

  p += sprintf(p,
               "state:       %s\n",state2str(cb->state,obuf));

 proc_read_param_ende:
  *eof = 1;
  return p - buf;
#undef CHECK_ENDE
} /* proc_read_param */

/* == PROC proc_read_hardware == */
int proc_read_hardware(char *buf, char **start, off_t offset, int count, 
                       int *eof, void *data)
{
  WL24Cb_t *cb = data;
  char *p = buf;

#define CHECK_ENDE if ((p-buf) > (count - 80)) goto proc_read_hw_ende

  p += sprintf(p,
               "card name:   %s\n"
               "fw date:     %s\n"
               "fw version:  %x.%x\n",
               cb->CardName, cb->FirmwareDate, cb->FWversion[0], cb->FWversion[1]);

  CHECK_ENDE;

  p += sprintf(p,
               "MAC addr:    %02X:%02X:%02X:%02X:%02X:%02X\n"
               "freq domain: x%x\n",
               cb->MacAddress[0],cb->MacAddress[1],cb->MacAddress[2],
               cb->MacAddress[3],cb->MacAddress[4],cb->MacAddress[5], 
               cb->FreqDomain);

 proc_read_hw_ende:
  *eof = 1;
  return p - buf;
#undef CHECK_ENDE
} /* proc_read_hardware_ende */


#if TRACE_NR_RECS > 0
/* == PROC proc_read_trace == */
int proc_read_trace(char *buf, char **start, off_t offset, int count, 
                    int *eof, void *data)
{
  WL24Cb_t *cb = data;
  char *p = buf;
  int tr; /* index of trace record to read */
  TraceEntry_t *te;
  int i;

#if 0
  printk(KERN_DEBUG "%s %s: offset %lu, cb->trace_nr %d\n", 
         cb->name, __FUNCTION__, offset, cb->trace_nr);
#endif

  if (offset == 0) {
    /* first call to proc_read_trace */
    cb->proc_read_trace_idx = 0;
    if (cb->trace_nr == 0) {
      *eof = 1;
      return 0;
    } else {
      /* find the oldest record */
      tr = cb->trace_nr >= TRACE_NR_RECS ? cb->trace_next : 0;
    }
  } else {
    /* following calls */
    tr =  cb->proc_read_trace_idx >= TRACE_NR_RECS ? 0 : cb->proc_read_trace_idx;
    if (tr == cb->trace_next) {
      *eof = 1;
      return 0;
    }
  }

  te = &cb->trace[tr];

  switch (te->id) {
  case TRACE_MSG_SENT:
  case TRACE_MSG_RCV:
    p += sprintf(p, "%s: %8u %s ",
                 te->id == TRACE_MSG_SENT ? " SENDMSG": " RCV_MSG",
                 te->u.first.jiffies, sigid2str(te->u.first.data[0]));
    for(i=1; i < te->len; i++)
      p += sprintf(p, "%02x ", te->u.first.data[i]);
    break;

  case TRACE_NEW_STATE:
    {
      char obuf1[12], obuf2[12];
      p += sprintf(p, "NEWSTATE: %8u %s -> %s", te->u.first.jiffies,
                   stateid2str(te->u.first.data[0],obuf1),
                   stateid2str(te->u.first.data[1],obuf2));
    }
    break;

  case TRACE_NEW_BSS_FOUND:
    p += sprintf(p, "  NEWBSS: %8u ch %d rssi %d cap x%02x%02x ",
                 te->u.first.jiffies,
                 te->u.first.data[0], te->u.first.data[1],
                 te->u.first.data[2], te->u.first.data[3]);
    p += sprintf(p, "BSSID %02x:%02x:%02x:%02x:%02x:%02x",
                 te->u.first.data[4], te->u.first.data[5],
                 te->u.first.data[6], te->u.first.data[7],
                 te->u.first.data[8], te->u.first.data[9]);
    break;

  case TRACE_TRY_NEW_BSS:
    p += sprintf(p, "  TRYBSS: %8u ch %d rssi %d cap x%02x%02x ",
                 te->u.first.jiffies,
                 te->u.first.data[0], te->u.first.data[1],
                 te->u.first.data[2], te->u.first.data[3]);
    p += sprintf(p, "BSSID %02x:%02x:%02x:%02x:%02x:%02x",
                 te->u.first.data[4], te->u.first.data[5],
                 te->u.first.data[6], te->u.first.data[7],
                 te->u.first.data[8], te->u.first.data[9]);
    break;

  case TRACE_DATA:
    p += sprintf(p, "    DATA:          ");
    for(i=0; i < te->len; i++)
      p += sprintf(p, "%02x ", te->u.follow.data[i]);
    break;

  default:
    p += sprintf(p, " UNKNOWN: x%02x", te->id);
  }

  *p++ = '\n';
  *p = '\0';

  cb->proc_read_trace_idx++;

#if 0
  printk(KERN_DEBUG "%s %s: dump trace entry %d: |%s| ",
         cb->name, __FUNCTION__, tr, buf);
  dumpk((uint8 *)te,sizeof(*te));
  printk("\n");
#endif
  
  *start = buf;

  return p - buf;

} /* proc_read_trace */
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
/* == PROC proc_write_debug == */
ssize_t proc_write_debug(struct file *fil, const char *inbuf ,
                         unsigned long len, void *priv)
{
  char buf[128]; /* max 18 char in input */
  WL24Cb_t *cb = priv;
  char const *data = buf;
  char *endp;
  uint32 val;

  len = MIN(sizeof(buf)-1, len);
  memcpy(buf, inbuf, len);
  buf[len] = '\0';

#if 0
  printk(KERN_DEBUG "%s %s: got %s\n", cb->name, __FUNCTION__, data);
#endif

#define FILL(field) \
 do { \
  while (isspace(*data)) {\
    if (++data >= (buf+len)) \
      goto proc_write_debug_ende; \
  } \
  if (data >= (buf+len)) \
    goto proc_write_debug_ende; \
  val = simple_strtol(data,&endp,0);\
  if (endp == data) \
    printk(KERN_DEBUG "%s %s: invalid value for " #field ": %s\n", cb->name, __FUNCTION__, data);\
  else {\
    data = endp;\
    cb->##field = val;\
  } \
 } while (0)

  FILL(dbg_mask);
  FILL(msg_from_dbg_mask);
  FILL(msg_to_dbg_mask);
  FILL(trace_mask);

 proc_write_debug_ende:
  return len;
#undef FILL
} /* proc_write_debug */


/* == PROC proc_read_debug == */
int proc_read_debug(char *buf, char **start, off_t offset,
                    int length, int *eof, void *data)
{
  WL24Cb_t *cb = data;

  if (offset != 0)
    return 0;
  else {
    *eof = 1;
    return sprintf(buf,
                   "dbg_mask:          %08x\n"
                   "msg_from_dbg_mask: %08x\n"
                   "msg_to_dbg_mask:   %08x\n"
                   "trace_mask:        %08x "
#if TRACE_NR_RECS > 0
                   "(ENABLED)"
#else
                   "(DISABLED)"
#endif
                   "\n",
                   cb->dbg_mask, cb->msg_from_dbg_mask,
                   cb->msg_to_dbg_mask, cb->trace_mask
                   );
  }
} /* proc_read_debug */

#else 
//LINUX_VERSION_CODE  >=  KERNEL_VERSION(2,4,0))

/* == PROC proc_write_debug == */
ssize_t proc_write_debug(struct file *fil, const char *inbuf ,
                         size_t len, loff_t *off)
{
  char buf[128]; /* max 18 char in input */
  const struct inode *ino = fil->f_dentry->d_inode;
  const struct proc_dir_entry *dp = ino->u.generic_ip;
  WL24Cb_t *cb = dp->data;
  char const *data = buf;
  char *endp;
  uint32 val;

  len = MIN(sizeof(buf)-1, len);
  memcpy(buf, inbuf, len);
  buf[len] = '\0';

#if 0
  printk(KERN_DEBUG "%s %s: got %s\n", cb->name, __FUNCTION__, data);
#endif

#define FILL(field) \
 do { \
  while (isspace(*data)) {\
    if (++data >= (buf+len)) \
      goto proc_write_debug_ende; \
  } \
  if (data >= (buf+len)) \
    goto proc_write_debug_ende; \
  val = simple_strtol(data,&endp,0);\
  if (endp == data) \
    printk(KERN_DEBUG "%s %s: invalid value for " #field ": %s\n", cb->name, __FUNCTION__, data);\
  else {\
    data = endp;\
    cb->##field = val;\
  } \
 } while (0)

  FILL(dbg_mask);
  FILL(msg_from_dbg_mask);
  FILL(msg_to_dbg_mask);
  FILL(trace_mask);

 proc_write_debug_ende:
  return len;
#undef FILL
} /* proc_write_debug */


/* == PROC proc_read_debug == */
ssize_t proc_read_debug(struct file *fil, char *buf, size_t sz, loff_t *off)
{
  const struct inode *ino = fil->f_dentry->d_inode;
  const struct proc_dir_entry *dp = ino->u.generic_ip;
  WL24Cb_t *cb = dp->data;

  if (fil->f_pos != 0)
    return 0;
  else {
    *off = sprintf(buf,
                   "dbg_mask:          %08x\n"
                   "msg_from_dbg_mask: %08x\n"
                   "msg_to_dbg_mask:   %08x\n"
                   "trace_mask:        %08x "
#if TRACE_NR_RECS > 0
                   "(ENABLED)"
#else
                   "(DISABLED)"
#endif
                   "\n",
                   cb->dbg_mask, cb->msg_from_dbg_mask,
                   cb->msg_to_dbg_mask, cb->trace_mask
                   );
    return *off;
  }
} /* proc_read_debug */

#endif //LINUX_VERSION_CODE  >=  KERNEL_VERSION(2,4,0))


/* == PROC proc_read_bss_set == */
int proc_read_bss_set(char *buf, char **start, off_t offset, int count, 
                      int *eof, void *data)
{
  WL24Cb_t *cb = data;
  BSSDesc_t *bss;
  char *p = buf;
  int i;
  char obuf[128];

#define CHECK_ENDE if ((p-buf) > (count - 80)) goto proc_read_bss_set_ende;

#if 0
  printk(KERN_DEBUG "%s: %s: *start %p offset %ld count %d\n", 
         cb->name, __FUNCTION__, *start, offset, count);
#endif

  if (offset == 0) {
    cb->proc_read_bss_idx = 0;
  }

  while (cb->proc_read_bss_idx < NR_BSS_DESCRIPTIONS) {
    if (cb->BSSset[cb->proc_read_bss_idx].valid)
      break;
    cb->proc_read_bss_idx++;
  }

#if 0
  printk(KERN_DEBUG "%s: %s: next index %d\n", cb->name, __FUNCTION__, 
         cb->proc_read_bss_idx);
#endif

  if (cb->proc_read_bss_idx >= NR_BSS_DESCRIPTIONS) {
    *eof = 1;
    return 0;
  }

#if 0
  printk(KERN_DEBUG "%s: %s: printing index %d\n", cb->name, __FUNCTION__, 
         cb->proc_read_bss_idx);
#endif

  bss = &cb->BSSset[cb->proc_read_bss_idx];

  if (cb->currBSS == cb->proc_read_bss_idx)
    p += sprintf(p, "current BSS\n");

  p += sprintf(p,
               "BSSID:           %02X:%02X:%02X:%02X:%02X:%02X\n"
               "SSID:            %s (",
               bss->BSSID[0],bss->BSSID[1],bss->BSSID[2],
               bss->BSSID[3],bss->BSSID[4],bss->BSSID[5],
               bss->SSID+2);
  CHECK_ENDE;

  for(i=0; i < bss->SSID[1] + 2; i++) {
    p+= sprintf(p, "%02x ", bss->SSID[i]);
  }

  CHECK_ENDE;

  p += sprintf(p,")\n");

  p += sprintf(p,
               "BSSType:         x%x\n",bss->BSSType);

  CHECK_ENDE;

  p += sprintf(p,
               "CapabilityInfo:  x%04x %s%s%s%s%s\n"
               "Channel:         %d\n",
               bss->CapabilityInfo,
               bss->CapabilityInfo & CAP_ESS ? "ESS," : "",
               bss->CapabilityInfo & CAP_IBSS ? "IBSS," : "",
               bss->CapabilityInfo & CAP_CF_POLLABLE ? "CF_POLLABLE," : "",
               bss->CapabilityInfo & CAP_CF_POLL_REQ ? "CF_POLL_REQ," : "",
               bss->CapabilityInfo & CAP_PRIVACY ? "PRIVACY," : "",
               bss->PHYpset[2]);

  CHECK_ENDE;

  p += sprintf(p,
               "BeaconPeriod:    x%x\n"
               "DTIMPeriod:      x%x\n"
               "Timestamp:       x%02x%02x%02x%02x%02x%02x%02x%02x\n"
               "LocalTime:       x%02x%02x%02x%02x%02x%02x%02x%02x\n",
               bss->BeaconPeriod,
               bss->DTIMPeriod,
               bss->Timestamp[0],bss->Timestamp[1],bss->Timestamp[2],bss->Timestamp[3],
               bss->Timestamp[4],bss->Timestamp[5],bss->Timestamp[6],bss->Timestamp[7],
               bss->LocalTime[0],bss->LocalTime[1],bss->LocalTime[2],bss->LocalTime[3],
               bss->LocalTime[4],bss->LocalTime[5],bss->LocalTime[6],bss->LocalTime[7]);

  CHECK_ENDE;

  p += sprintf(p,
               "PHYpset:         x%02x%02x%02x\n",
               bss->PHYpset[0],bss->PHYpset[1],bss->PHYpset[2]);

  CHECK_ENDE;

  p += sprintf(p,
               "CFpset:          x%02x%02x%02x%02x%02x%02x%02x%02x\n",
               bss->CFpset[0],bss->CFpset[1],bss->CFpset[2],bss->CFpset[3],
               bss->CFpset[4],bss->CFpset[5],bss->CFpset[6],bss->CFpset[7]);

  CHECK_ENDE;

  p += sprintf(p,
               "IBSSpset:        x%02x%02x%02x%02x\n",
               bss->IBSSpset[0],bss->IBSSpset[1],bss->IBSSpset[2],bss->IBSSpset[3]
               );

  CHECK_ENDE;

  p += sprintf(p,
               "BSSBasicRateSet: %s x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
               "RSSI(last Scan): x%02x\n"
               "RSSI(last data): x%02x\n\n",
               rateset2str(bss->BSSBasicRateSet,obuf, sizeof(obuf)),
               bss->BSSBasicRateSet[0],bss->BSSBasicRateSet[1],bss->BSSBasicRateSet[2],
               bss->BSSBasicRateSet[3],bss->BSSBasicRateSet[4],bss->BSSBasicRateSet[5],
               bss->BSSBasicRateSet[6],bss->BSSBasicRateSet[7],bss->BSSBasicRateSet[8],
               bss->BSSBasicRateSet[9],
               bss->ScanRSSI, bss->MdIndRSSI);

         
 proc_read_bss_set_ende:
  *eof = 0;

  *start = buf;

#if 0
  printk(KERN_DEBUG "%s: %s: returning %d\n",
         cb->name, __FUNCTION__, p - buf);
#endif

  cb->proc_read_bss_idx++;

  return p - buf;
#undef CHECK_ENDE

} /* proc_read_bss_set */


const static struct _entries {
  char const *name;
  read_proc_t *read_fct;
} entries[] = {
  {"param", proc_read_param},
  {"hardware", proc_read_hardware},
#if TRACE_NR_RECS > 0
  {"trace", proc_read_trace},
#endif
  {"bss_set", proc_read_bss_set},
};
int const elen = sizeof(entries) / sizeof(struct _entries);

#define PROC_SUB_DIR "wl24_cs"

static struct proc_dir_entry *proc_subdir; /* the subdir for all instances of this driver */

/* == PROC wl24n_create_procdir ==
   creates the common subdir for all driver instances:
   /proc/driver + PROC_SUB_DIR (see above) */
void wl24n_create_procdir(void)
{
  if ((proc_subdir=proc_mkdir(PROC_SUB_DIR, proc_root_driver)) == NULL) {
    printk(KERN_WARNING "%s: cannot create dir " PROC_SUB_DIR " in /proc/driver\n",
           __FUNCTION__);
    return;
  }

#if 0
  printk(KERN_DEBUG "%s: created dir " PROC_SUB_DIR " in /proc/driver\n",
         __FUNCTION__);
#endif

} /* wl24n_create_procdir */

/* == PROC wl24n_remove_procdir ==
   removes the common subdir */
void wl24n_remove_procdir(void)
{
  remove_proc_entry(PROC_SUB_DIR, proc_root_driver);
}


/* == PROC create_proc_entries ==
   create under /proc/driver the proc entries:
   wl24_cs/<N>/{param,hardware,debug,bss_set}
   where <N> is the number from the device name eth<N> */
void create_proc_entries(WL24Cb_t *cb)
{
  int i;
  char dir_str[5];

  assert(cb->name);
  if (memcmp(cb->name,"eth",3)) {
    printk(KERN_WARNING "%s %s: name does not start with \"eth\"\n",
           cb->name, __FUNCTION__);
    return;
  }

  strncpy(dir_str,cb->name+3,sizeof(dir_str));
  dir_str[sizeof(dir_str)-1] = '\0';

#if 0
  printk(KERN_DEBUG "%s %s: creating dir %s in /proc/driver/" PROC_SUB_DIR "/\n",
         cb->name, __FUNCTION__, dir_str);
#endif

  if ((cb->pdir=proc_mkdir(dir_str, proc_subdir)) == NULL) {
    printk(KERN_WARNING "%s %s: cannot create dir %s in /proc/driver/" PROC_SUB_DIR "/\n",
           cb->name, __FUNCTION__, dir_str);
    return;
  }

  for(i=0; i < elen; i++) {
    if (!create_proc_read_entry(entries[i].name, 0444, cb->pdir,
                                entries[i].read_fct, cb)) {
      printk(KERN_WARNING "%s %s: cannot create entry %s in /proc/%s\n",
             cb->name, __FUNCTION__, entries[i].name, dir_str);
      return;
    }
  }

  /* create "debug" file for read & write */
  {
    struct proc_dir_entry *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0))
    static struct file_operations debug_ops = {
      read:          proc_read_debug,
      write:         proc_write_debug,
    };
#endif

    entry = create_proc_entry("debug", S_IRUGO|S_IWUGO, cb->pdir);
    assert(entry != NULL);
    if (entry != NULL) {
      entry->data = cb;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
      entry->read_proc = proc_read_debug;
      entry->write_proc = proc_write_debug;
#else
      entry->proc_fops = &debug_ops;
#endif
    }
  }
} /* create_proc_entries */

/* == PROC delete_proc_entries == */
void delete_proc_entries(WL24Cb_t *cb)
{
  char name[128];
  int i;

  for(i=0; i < elen; i++)
    remove_proc_entry(entries[i].name, cb->pdir);

  remove_proc_entry("debug", cb->pdir);

  sprintf(name, PROC_SUB_DIR "/%s",cb->name+3);
  remove_proc_entry(name, NULL);
} /* delete_proc_entries */


/* TODO:

   - Readme überarbeiten
   - Testcode entfernen (restart_card,

*/
