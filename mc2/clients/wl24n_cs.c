/* $Id: wl24n_cs.c,v 1.6 2003/02/01 13:43:59 jal2 Exp $ */

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

/* This file implements the PCMCIA i/f for a Elsa Airlancer MC2
   WLAN card. It's derived from the dummy_cs.c of
   David Hinds PCMCIA package, version 3.1.30 and wvlan_cs.c */

#include <pcmcia/config.h>
#include <pcmcia/k_compat.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/ioport.h>
// ??? needed
//#include <linux/netdevice.h>
#include <asm/io.h>
#include <asm/system.h>

#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>
#include <pcmcia/bus_ops.h>

// some adaptions for 2.2.x kernels
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
#define MODULE_LICENSE(x)  extern int __bogus_decl
#endif

#include <linux/wireless.h>
#if WIRELESS_EXT < 5
#error "Wireless extension v5 or newer required"
#endif
#define WIRELESS_SPY            // enable iwspy support
#undef HISTOGRAM                // disable histogram of signal levels

// This is needed for station_name, but we may not compile WIRELESS_EXT
#ifndef IW_ESSID_MAX_SIZE
#define IW_ESSID_MAX_SIZE       32
#endif /* IW_ESSID_MAX_SIZE */

#include "wl24n.h" /* public i/f of wl24n.c */

// for first tests
#undef PCMCIA_DEBUG
#define PCMCIA_DEBUG 3

/* Module parameters */

#define INT_MODULE_PARM(n, v) static int n = v; MODULE_PARM(n, "i")

MODULE_AUTHOR("Alfred Arnold alfred@ccac.rwth-aachen.de\n"
              "Joerg Albert <joerg.albert@gmx.de>\nHeiko Kirschke\n");
MODULE_DESCRIPTION("ELSA Airlancer MC-2 WLAN PCMCIA driver");
MODULE_LICENSE("GPL");
/* Newer, simpler way of listing specific interrupts */
static int irq_list[4] = { -1 };
MODULE_PARM(irq_list, "1-4i");

/* Release IO ports after configuration? */
INT_MODULE_PARM(free_ports, 0);

/* The old way: bit map of interrupts to choose from */
/* This means pick from 15, 14, 12, 11, 10, 9, 7, 5, 4, and 3 */
INT_MODULE_PARM(irq_mask, 0xdeb8);

INT_MODULE_PARM(trace_mask,0xffffffff);
MODULE_PARM_DESC(trace_mask,"controls trace entries in /proc/driver/mc2/<N>/trace"
                 "(if TRACE_NR_RECS > 0 during compile time in wl24n.c,"
                 " see wl24n.h for details)");

INT_MODULE_PARM(dbg_mask,0xffffffff);
MODULE_PARM_DESC(dbg_mask,"controls common debug msgs, see wl24n.h for meaning of bits");

//INT_MODULE_PARM(msg_to_dbg_mask, 0xffffffff);
INT_MODULE_PARM(msg_to_dbg_mask,
                0xffffffff & ~(DBG_TXDATA_REQ|DBG_TXDATA_REQ_DATA));

MODULE_PARM_DESC(msg_to_dbg_mask,
                 "controls debugging of msgs to card, see wl24n.h for meaning of bits");

//INT_MODULE_PARM(msg_from_dbg_mask, 0xffffffff);
INT_MODULE_PARM(msg_from_dbg_mask, 
                0xffffffff & ~(DBG_MDCFM | DBG_MDIND | 
                               DBG_MDIND_HEADER | DBG_MDIND_DATA | 
                               DBG_RX_FRAGMENTS | DBG_UNSUCC_MDCFM_FAIL));
MODULE_PARM_DESC(msg_from_dbg_mask,
                 "controls debugging of msgs from card, see wl24n.h for meaning of bits");

INT_MODULE_PARM(LLCType,LLCType_WaveLan);
MODULE_PARM_DESC(LLCType,
                 "type of LLC: WaveLan (1) or IEEE_802_11 (2)");

INT_MODULE_PARM(networktype, BSSType_Independent);
MODULE_PARM_DESC(networktype,
                 "type of BSS to connect to: access point (0), ad-hoc (1) or both (2)");

static char networkname[2*IW_ESSID_MAX_SIZE+1] = "\0";
MODULE_PARM(networkname, "c" __MODULE_STRING(64));
MODULE_PARM_DESC(networkname,
                 "ID of ESS (or IBSS) to connect to (empty string matches all)");

INT_MODULE_PARM(nwn_is_hex, 0);
MODULE_PARM_DESC(nwn_is_hex, "is networkname given as a sequence of hex digits ?");

INT_MODULE_PARM(Channel, 4);
MODULE_PARM_DESC(Channel,
                 "if networktype == ad-hoc(1) and if scanning for networkname "
                 "failed several times this channel is used to setup an IBSS");

/*
   All the PCMCIA modules use PCMCIA_DEBUG to control debugging.  If
   you do not define PCMCIA_DEBUG at all, all the debug code will be
   left out.  If you compile with PCMCIA_DEBUG=0, the debug code will
   be present but disabled -- but it can then be enabled for specific
   modules at load time with a 'pc_debug=#' option to insmod.
*/

#ifdef PCMCIA_DEBUG
INT_MODULE_PARM(pc_debug, PCMCIA_DEBUG);
#define DEBUG(n, args...) if (pc_debug>(n)) printk(KERN_DEBUG args)
/* VERSION is passed from the Makefile in a define as a string ! */
static char *version __attribute__((unused)) =
__FILE__ " v" WL24_VERSION " $Id: wl24n_cs.c,v 1.6 2003/02/01 13:43:59 jal2 Exp $";
#else
#define DEBUG(n, args...)
#endif
 
/*====================================================================*/

/*
   The event() function is this driver's Card Services event handler.
   It will be called by Card Services when an appropriate card status
   event is received.  The config() and release() entry points are
   used to configure or release a socket, in response to card
   insertion and ejection events.  They are invoked from the dummy
   event handler. 
*/

static void mc2_config(dev_link_t *link);
static void mc2_release(u_long arg);
static int mc2_event(event_t event, int priority,
                     event_callback_args_t *args);

/*
   The attach() and detach() entry points are used to create and destroy
   "instances" of the driver, where each instance represents everything
   needed to manage one actual PCMCIA card.
*/

static dev_link_t *mc2_attach(void);
static void mc2_detach(dev_link_t *);

/*
   The dev_info variable is the "key" that is used to match up this
   device driver with appropriate cards, through the card configuration
   database.
*/

static dev_info_t dev_info = "wl24_cs";

/*
   A linked list of "instances" of the device.  Each actual
   PCMCIA card corresponds to one device instance, and is described
   by one dev_link_t structure (defined in ds.h).
*/

static dev_link_t *dev_list = NULL;

/*
   A dev_link_t structure has fields for most things that are needed
   to keep track of a socket, but there will usually be some device
   specific information that also needs to be kept track of.  The
   'priv' pointer in a dev_link_t structure can be used to point to
   a device-specific private data structure, like this.

   To simplify the data structure handling, we actually include the
   dev_link_t structure in the device's private data structure.

   A driver needs to provide a dev_node_t structure for each device
   on a card.  In some cases, there is only one device per card (for
   example, ethernet cards, modems).  In other cases, there may be
   many actual or logical devices (SCSI adapters, memory cards with
   multiple partitions).  The dev_node_t structures need to be kept
   in a linked list starting at the 'dev' field of a dev_link_t
   structure.  We allocate them in the card's private data structure,
   because they generally shouldn't be allocated dynamically.

   In this case, we also provide a flag to indicate if a device is
   "stopped" due to a power management event, or card ejection.  The
   device IO routines can use a flag like this to throttle IO to a
   card that is not ready to accept it.

   The bus_operations pointer is used on platforms for which we need
   to use special socket-specific versions of normal IO primitives
   (inb, outb, readb, writeb, etc) for card IO.
*/
   
typedef struct local_info_t {
  dev_link_t            link;
  dev_node_t            node;
  int                   stop;
  struct bus_operations *bus;
  void *mc2_priv; /* we got this from wl24_card_init() */
} local_info_t;


int hex2bin(unsigned char *ib, unsigned char *ob)
     /* convert a \0 terminated string of hex digits into the binary repr.
   and returns the number of bytes created.
   ib and ob may be the same buffer ! */
{
  int i=0;
  unsigned char val = 0;
#define HEX2BIN(x) \
 ((x) <= '9' ? (x)-'0' :\
  (x) >= 'a' && (x) <= 'f' ? (x)-'a'+10 : (x)-'A'-10)

  while (*ib) {
    if (i%2)
      *ob++ = (val<<4) | HEX2BIN(*ib);
    else
      val = HEX2BIN(*ib);
    i++;
    ib++;
  }

  if (i%2) {
    /* we got an odd number of hexdigits - quietly assume a trailing 0 */
    *ob = val<<4;
    i++;
  }

  return i/2;
}

/* == PROC wl24n_cs_interrupt == */
/* a wrapper around wl24n_interrupt in a try
   to support shared interrupts */
void wl24n_cs_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
  local_info_t *local = dev_id;
  static conf_reg_t reg = {0, CS_READ, CISREG_CCSR, 0};
  CardServices(AccessConfigurationRegister, local->link.handle, &reg);
  if (reg.Value & CCSR_INTR_PENDING)
    /* only call it when an interrupt is pending */
    wl24n_interrupt(irq, local->mc2_priv, regs);
}


/*====================================================================*/

static void cs_error(client_handle_t handle, int func, int ret)
{
  error_info_t err = { func, ret };
  CardServices(ReportError, handle, &err);
}

/*------------------------------------------------------------------*/
/*
 * Sometimes, mc2_detach can't be performed following a call from
 * cardmgr (device still open, pcmcia_release not done) and the device
 * is put in a STALE_LINK state and remains in memory.
 *
 * This function run through our current list of device and attempt
 * another time to remove them. We hope that since last time the
 * device has properly been closed.
 *
 * (called by mc2_attach() & cleanup_module())
 */
static void
mc2_flush_stale_links(void)
{
  dev_link_t *  link;           /* Current node in linked list */
  dev_link_t *  next;           /* Next node in linked list */

  DEBUG(0, "mc2_flush_stale_links(0x%p)\n", dev_list);

  /* Go through the list */
  for (link = dev_list; link; link = next) {
    next = link->next;
    
    /* Check if in need of being removed */
    if ( (link->state & DEV_STALE_LINK) ||
         (!(link->state & DEV_PRESENT)))
      mc2_detach(link);
  }

} /* mc2_flush_stale_links */

/*======================================================================

    mc2_attach() creates an "instance" of the driver, allocating
    local data structures for one device.  The device is registered
    with Card Services.

    The dev_link structure is initialized, but we don't actually
    configure the card at this point -- we wait until we receive a
    card insertion event.
    
======================================================================*/

static dev_link_t *mc2_attach(void)
{
  local_info_t *local;
  dev_link_t *link;
  client_reg_t client_reg;
  int ret, i;
    
  DEBUG(0, "mc2_attach()\n");

  /* do some clean up */
  mc2_flush_stale_links();

  /* Allocate space for private device-specific data */
  local = kmalloc(sizeof(local_info_t), GFP_KERNEL);
  if (!local) return NULL;
  memset(local, 0, sizeof(local_info_t));
  link = &local->link;
  link->priv = local;

  /* Initialize the dev_link_t structure */
  link->release.function = &mc2_release;
  link->release.data = (u_long)link;

  /* Interrupt setup */
  /* link->irq.Attributes = IRQ_TYPE_EXCLUSIVE | IRQ_HANDLE_PRESENT; */

  /* try to share interrupt */
  link->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING | IRQ_FIRST_SHARED |
    IRQ_HANDLE_PRESENT;

  link->irq.IRQInfo1 = IRQ_INFO2_VALID|IRQ_LEVEL_ID;
  if (irq_list[0] == -1)
    link->irq.IRQInfo2 = irq_mask;
  else
    for (i = 0; i < 4; i++)
      link->irq.IRQInfo2 |= 1 << irq_list[i];

  link->irq.Handler = wl24n_cs_interrupt;
    
  /*
    General socket configuration defaults can go here.  In this
    client, we assume very little, and rely on the CIS for almost
    everything.  In most clients, many details (i.e., number, sizes,
    and attributes of IO windows) are fixed by the nature of the
    device, and can be hard-wired here.
  */
  link->conf.Attributes = CONF_ENABLE_IRQ;
  link->conf.Vcc = 50; /* also init. in mc2_config ??? */
  link->conf.IntType = INT_MEMORY_AND_IO;

  /* additional config from original sw:
     TODO: check what is necessary
     and what can be taken from the CIS */
#if 1
  /* The io structure describes IO port mapping */
  link->io.NumPorts1 = 16;
  link->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
  link->io.IOAddrLines = 5;
  //link->conf.Attributes = CONF_ENABLE_IRQ;
  link->conf.ConfigIndex = 1;
  link->conf.Present = PRESENT_OPTION;
#endif

  /* Register with Card Services */
  link->next = dev_list;
  dev_list = link;
  client_reg.dev_info = &dev_info;
  client_reg.Attributes = INFO_IO_CLIENT | INFO_CARD_SHARE;
  client_reg.EventMask =
    CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
    CS_EVENT_RESET_PHYSICAL | CS_EVENT_CARD_RESET |
    CS_EVENT_PM_SUSPEND | CS_EVENT_PM_RESUME;
  client_reg.event_handler = &mc2_event;
  client_reg.Version = 0x0210;
  client_reg.event_callback_args.client_data = link;
    
  ret = CardServices(RegisterClient, &link->handle, &client_reg);
  if (ret != CS_SUCCESS) {
    cs_error(link->handle, RegisterClient, ret);
    mc2_detach(link);
    return NULL;
  }

  return link;
} /* mc2_attach */


/*======================================================================

    This deletes a driver "instance".  The device is de-registered
    with Card Services.  If it has been released, all local data
    structures are freed.  Otherwise, the structures will be freed
    when the device is released.

======================================================================*/

static void mc2_detach(dev_link_t *link)
{
  dev_link_t **linkp;

  DEBUG(0, "mc2_detach(0x%p)\n", link);
    
  /* Locate device structure */
  for (linkp = &dev_list; *linkp; linkp = &(*linkp)->next)
    if (*linkp == link) break;
  if (*linkp == NULL)
    return;

  del_timer(&link->release);
  if (link->state & DEV_CONFIG) {

    /* try to release first */
    mc2_release((u_long)link);

    if (link->state & DEV_STALE_CONFIG) {
      DEBUG(0, "mc2: detach postponed, '%s' "
            "still locked\n", link->dev->dev_name);
      link->state |= DEV_STALE_LINK;
      return;
    }
  }
    
  /* Break the link with Card Services */
  if (link->handle)
    CardServices(DeregisterClient, link->handle);
    
  /* Unlink device structure, and free it */
  *linkp = link->next;
    
  if (link->priv) {
    /* stop the device and dealloc buffers alloced in wl24_card_init() */
    wl24n_card_stop(((local_info_t *)link->priv)->mc2_priv);
    kfree(link->priv);
  }
} /* mc2_detach */

/*======================================================================

    mc2_config() is scheduled to run after a CARD_INSERTION event
    is received, to configure the PCMCIA socket, and to make the
    device available to the system.
    
======================================================================*/

#define CS_CHECK(fn, args...) \
while ((last_ret=CardServices(last_fn=(fn),args))!=0) goto cs_failed

#define CFG_CHECK(fn, args...) \
if (CardServices(fn, args) != 0) goto next_entry

static void mc2_config(dev_link_t *link)
{
  client_handle_t handle = link->handle;
  local_info_t *dev = link->priv;
  tuple_t tuple;
  cisparse_t parse;
  int last_fn, last_ret;
  u_char buf[64];
  config_info_t conf;
  win_req_t req;
  memreq_t map;
  cistpl_cftable_entry_t dflt = { 0 };
  char *dev_name = NULL; /* get the device name from wl24n_card_init() */
  int nw_len; /* length of networkname */


  DEBUG(0, "mc2_config(0x%p)\n", link);

  /*
    This reads the card's CONFIG tuple to find its configuration
    registers.
  */
  tuple.DesiredTuple = CISTPL_CONFIG;
  tuple.Attributes = 0;
  tuple.TupleData = buf;
  tuple.TupleDataMax = sizeof(buf);
  tuple.TupleOffset = 0;
  CS_CHECK(GetFirstTuple, handle, &tuple);
  CS_CHECK(GetTupleData, handle, &tuple);
  CS_CHECK(ParseTuple, handle, &tuple, &parse);
  link->conf.ConfigBase = parse.config.base;
  link->conf.Present = parse.config.rmask[0];
    
  /* Configure card */
  link->state |= DEV_CONFIG;

  /* Look up the current Vcc */
  CS_CHECK(GetConfigurationInfo, handle, &conf);
  link->conf.Vcc = conf.Vcc;

  /*
    In this loop, we scan the CIS for configuration table entries,
    each of which describes a valid card configuration, including
    voltage, IO window, memory window, and interrupt settings.

    We make no assumptions about the card to be configured: we use
    just the information available in the CIS.  In an ideal world,
    this would work for any PCMCIA card, but it requires a complete
    and accurate CIS.  In practice, a driver usually "knows" most of
    these things without consulting the CIS, and most client drivers
    will only use the CIS to fill in implementation-defined details.
  */
  tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
  CS_CHECK(GetFirstTuple, handle, &tuple);
  while (1) {
    cistpl_cftable_entry_t *cfg = &(parse.cftable_entry);
    CFG_CHECK(GetTupleData, handle, &tuple);
    CFG_CHECK(ParseTuple, handle, &tuple, &parse);

    if (cfg->flags & CISTPL_CFTABLE_DEFAULT) dflt = *cfg;
    if (cfg->index == 0) goto next_entry;
    link->conf.ConfigIndex = cfg->index;
        
    /* Use power settings for Vcc and Vpp if present */
    /*  Note that the CIS values need to be rescaled */
    if (cfg->vcc.present & (1<<CISTPL_POWER_VNOM)) {
      if (conf.Vcc != cfg->vcc.param[CISTPL_POWER_VNOM]/10000)
        goto next_entry;
    } else if (dflt.vcc.present & (1<<CISTPL_POWER_VNOM)) {
      if (conf.Vcc != dflt.vcc.param[CISTPL_POWER_VNOM]/10000)
        goto next_entry;
    }
            
    if (cfg->vpp1.present & (1<<CISTPL_POWER_VNOM))
      link->conf.Vpp1 = link->conf.Vpp2 =
        cfg->vpp1.param[CISTPL_POWER_VNOM]/10000;
    else if (dflt.vpp1.present & (1<<CISTPL_POWER_VNOM))
      link->conf.Vpp1 = link->conf.Vpp2 =
        dflt.vpp1.param[CISTPL_POWER_VNOM]/10000;
        
    /* Do we need to allocate an interrupt? */
    if (cfg->irq.IRQInfo1 || dflt.irq.IRQInfo1)
      link->conf.Attributes |= CONF_ENABLE_IRQ;
        
    /* IO window settings */
    link->io.NumPorts1 = link->io.NumPorts2 = 0;
    if ((cfg->io.nwin > 0) || (dflt.io.nwin > 0)) {
      cistpl_io_t *io = (cfg->io.nwin) ? &cfg->io : &dflt.io;
      link->io.Attributes1 = IO_DATA_PATH_WIDTH_AUTO;
      if (!(io->flags & CISTPL_IO_8BIT))
        link->io.Attributes1 = IO_DATA_PATH_WIDTH_16;
      if (!(io->flags & CISTPL_IO_16BIT))
        link->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
      link->io.IOAddrLines = io->flags & CISTPL_IO_LINES_MASK;
      link->io.BasePort1 = io->win[0].base;
      link->io.NumPorts1 = io->win[0].len;
      if (io->nwin > 1) {
        link->io.Attributes2 = link->io.Attributes1;
        link->io.BasePort2 = io->win[1].base;
        link->io.NumPorts2 = io->win[1].len;
      }
      /* This reserves IO space but doesn't actually enable it */
      CFG_CHECK(RequestIO, link->handle, &link->io);
    }

    /*
      Now set up a common memory window, if needed.  There is room
      in the dev_link_t structure for one memory window handle,
      but if the base addresses need to be saved, or if multiple
      windows are needed, the info should go in the private data
      structure for this device.

      Note that the memory window base is a physical address, and
      needs to be mapped to virtual space with ioremap() before it
      is used.
    */
    if ((cfg->mem.nwin > 0) || (dflt.mem.nwin > 0)) {
      cistpl_mem_t *mem =
        (cfg->mem.nwin) ? &cfg->mem : &dflt.mem;
      req.Attributes = WIN_DATA_WIDTH_16|WIN_MEMORY_TYPE_CM;
      req.Attributes |= WIN_ENABLE;
      req.Base = mem->win[0].host_addr;
      req.Size = mem->win[0].len;
      if (req.Size < 0x1000)
        req.Size = 0x1000;
      req.AccessSpeed = 0;
      link->win = (window_handle_t)link->handle;
      CFG_CHECK(RequestWindow, &link->win, &req);
      map.Page = 0; map.CardOffset = mem->win[0].card_addr;
      CFG_CHECK(MapMemPage, link->win, &map);
    }
    /* If we got this far, we're cool! */
    break;
        
  next_entry:
    if (link->io.NumPorts1)
      CardServices(ReleaseIO, link->handle, &link->io);
    CS_CHECK(GetNextTuple, handle, &tuple);
  }

  /* init the card after we got the io addresses etc. 
     Please note, that the irq value is set to 0, which is false,
     but who evaluates the dev->irq (but ifconfig ?) 
     But we need the mc2_priv for the RequestIRQ call below, so we must
     call it before. On the other hand the RequestIRQ returns the
     correct AssignedIRQ to us ... */
  link->open = 0;
  if (nwn_is_hex) 
    /* condense the hex string into a binary one */
    nw_len = hex2bin(networkname,networkname);
  else
    nw_len = strlen(networkname);

  if ((dev->mc2_priv=wl24n_card_init(dbg_mask, msg_to_dbg_mask,
                                     msg_from_dbg_mask,
                                     link->io.BasePort1,
                                     0, /* was: link->irq.AssignedIRQ */
                                     LLCType, networktype, networkname,
                                     nw_len, Channel, &link->open, 
                                     &dev_name, trace_mask)) == NULL) {
    printk(KERN_DEBUG "wl24_card_init failed\n");
    mc2_release((u_long)link);
    return;
  } 

  /*
    Allocate an interrupt line.  Note that this does not assign a
    handler to the interrupt, unless the 'Handler' member of the
    irq structure is initialized.
  */

  if (link->conf.Attributes & CONF_ENABLE_IRQ) {

    /* if we use the wrapper wl24n_cs_interrupt, we must
       pass dev here ! */
    //link->irq.Instance = dev->mc2_priv;
    link->irq.Instance = dev;

    CS_CHECK(RequestIRQ, link->handle, &link->irq);
    printk(KERN_DEBUG "%s: request irq %d at card service\n",
           dev_name, link->irq.AssignedIRQ);
  }

  /*
    This actually configures the PCMCIA socket -- setting up
    the I/O windows and the interrupt mapping, and putting the
    card and host interface into "Memory and IO" mode.
  */
  CS_CHECK(RequestConfiguration, link->handle, &link->conf);

  /* this will read the MAC addr etc. and enter it into the netdevice struct.
     -> we must do it _after_ the RequestConfiguration ! */
  {
    int i;
    for (i=0; i < 10; i++)
      if (wl24n_card_reset(dev->mc2_priv))
        break;
    if (i >= 10) {
      printk(KERN_WARNING "%s: cannot reset card - giving up\n", dev_name);
      mc2_detach(link); /* calls mc2_release((u_long)link), too */
      return;
    }
  }

  /*
    We can release the IO port allocations here, if some other
    driver for the card is going to loaded, and will expect the
    ports to be available.
  */
  if (free_ports) {
    if (link->io.BasePort1)
      release_region(link->io.BasePort1, link->io.NumPorts1);
    if (link->io.BasePort2)
      release_region(link->io.BasePort2, link->io.NumPorts2);
  }

  /*
    At this point, the dev_node_t structure(s) need to be
    initialized and arranged in a linked list at link->dev.
  */
  dev->node.major = dev->node.minor = 0;
  dev->node.next = NULL; /* only one elem in list at link->dev*/
  strcpy(dev->node.dev_name, dev_name);

  link->dev = &dev->node;

  /* Finally, report what we've done */
  printk(KERN_INFO "%s: %s, version " WL24_VERSION 
         ", $Id: wl24n_cs.c,v 1.6 2003/02/01 13:43:59 jal2 Exp $, compiled "
         __DATE__ " " __TIME__ "\n", 
         dev->node.dev_name, __FILE__);
  printk(KERN_INFO "%s: index 0x%02x: Vcc %d.%d",
         dev->node.dev_name, link->conf.ConfigIndex,
         link->conf.Vcc/10, link->conf.Vcc%10);
  if (link->conf.Vpp1)
    printk(", Vpp %d.%d", link->conf.Vpp1/10, link->conf.Vpp1%10);
  if (link->conf.Attributes & CONF_ENABLE_IRQ)
    printk(", irq %d", link->irq.AssignedIRQ);
  if (link->io.NumPorts1)
    printk(", io 0x%04x-0x%04x  %d lines %s", link->io.BasePort1,
           link->io.BasePort1+link->io.NumPorts1-1,
           link->io.IOAddrLines,
           link->io.Attributes1 == IO_DATA_PATH_WIDTH_AUTO ? "AUTO" :
           link->io.Attributes1 == IO_DATA_PATH_WIDTH_16 ? "16BIT" :
           "8BIT");
  if (link->io.NumPorts2)
    printk(" & 0x%04x-0x%04x", link->io.BasePort2,
           link->io.BasePort2+link->io.NumPorts2-1);
  if (link->win)
    printk(", mem 0x%06lx-0x%06lx", req.Base,
           req.Base+req.Size-1);
  printk("\n");
    
  link->state &= ~DEV_CONFIG_PENDING;
  return;

 cs_failed:
  cs_error(link->handle, last_fn, last_ret);
  mc2_release((u_long)link);

} /* mc2_config */

/*======================================================================

    After a card is removed, mc2_release() will unregister the net
    device, and release the PCMCIA configuration.  If the device is
    still open, this will be postponed until it is closed.
    
======================================================================*/

static void mc2_release(u_long arg)
{
  dev_link_t *link = (dev_link_t *)arg;

  DEBUG(1,"mc2_release(0x%p)\n", link);

  if (link->open) {
    DEBUG(1, "mc2_release: postponed, '%s' still open\n",
          link->dev->dev_name);
    link->state |= DEV_STALE_CONFIG;
    return;
  }

  /* Unlink the device chain */
  link->dev = NULL;
    
  /* Don't bother checking to see if these succeed or not */
  CardServices(ReleaseConfiguration, link->handle);
  CardServices(ReleaseIO, link->handle, &link->io);
  CardServices(ReleaseIRQ, link->handle, &link->irq);
  link->state &= ~(DEV_CONFIG|DEV_STALE_CONFIG);

  /* mc2_detach must not be called from here, because mc2_release runs on
     interrupt level (called by some timer in soft_irq) und mc2_detach
     calls unregister_netdev() ! */
  //  if (link->state & DEV_STALE_LINK)
  //    /* detach was postponed before */
  //    mc2_detach(link);
  
} /* mc2_release */


/* == PROC mc2_event == */
static int mc2_event(event_t event, int priority,
                     event_callback_args_t *args)
{
  dev_link_t *link = args->client_data;

  DEBUG(1, "mc2_event(0x%06x)\n", event);
    
  switch (event) {

  case CS_EVENT_CARD_REMOVAL:
    link->state &= ~DEV_PRESENT;
    if (link->state & DEV_CONFIG) {
      /* stop the net i/f of the driver */
      wl24n_card_netif_stop(((local_info_t *)link->priv)->mc2_priv);
      link->release.expires = RUN_AT(HZ/20);
      add_timer(&link->release);
    }
    break;

  case CS_EVENT_CARD_INSERTION:
    link->state |= DEV_PRESENT | DEV_CONFIG_PENDING;
    mc2_config(link);
    break;

  case CS_EVENT_PM_SUSPEND:
    link->state |= DEV_SUSPEND;
    /* Fall through... */

  case CS_EVENT_RESET_PHYSICAL:
    if (link->state & DEV_CONFIG) {
      if (link->open) {
        wl24n_card_netif_stop(((local_info_t *)
                               link->priv)->mc2_priv);
      }
      CardServices(ReleaseConfiguration, link->handle);
    }
    break;

  case CS_EVENT_PM_RESUME:
    link->state &= ~DEV_SUSPEND;
    /* Fall through... */
  case CS_EVENT_CARD_RESET:
    if (link->state & DEV_CONFIG) {
      CardServices(RequestConfiguration, link->handle, &link->conf);
      if (link->open) {
        wl24n_card_reset(((local_info_t *)link->priv)->mc2_priv);
      }
    }
    break;

  default:
    printk(KERN_WARNING "mc2_event: unknown event x%08x\n",event);
  } /* switch (event) */

  return 0;
} /* mc2_event */

/*====================================================================*/
static int __init mc2_init(void)
{
  servinfo_t serv;
  CardServices(GetCardServicesInfo, &serv);
  if (serv.Revision != CS_RELEASE_CODE) {
    printk(KERN_NOTICE "wl24_cs: Card Services release does not match!\n"
           "Compiled with 0x%x, but current is 0x%lx\n", 
           CS_RELEASE_CODE, (long)serv.Revision);
    /* return -1; */
  }

  wl24n_create_procdir();

#ifdef PCMCIA_DEBUG
  if (pc_debug > 2) {
    /* dump the module parameter */
    int i;
    printk(KERN_DEBUG __FILE__  ":module parameters:\n");
    printk(KERN_DEBUG __FILE__ ": irq_list: ");
    i=0;
    while (i < 4 && irq_list[i] > 0) {
      printk("%d ",irq_list[i]);
      i++;
    }
    printk("\n");

    printk(KERN_DEBUG __FILE__  ": free_ports: %d irq_mask: x%x "\
           "trace_mask x%x\n",
           free_ports, irq_mask, trace_mask);
    printk(KERN_DEBUG __FILE__  ": dbg_mask x%x msg_to_dbg_mask: x%x "
           "msg_from_dbg_mask x%x\n",
           dbg_mask, msg_to_dbg_mask, msg_from_dbg_mask);
    printk(KERN_DEBUG __FILE__  ": LLCType %d networktype %d networkname %s "
           "nwn_is_hex %d\n",
           LLCType, networktype, networkname, nwn_is_hex);
    printk(KERN_DEBUG __FILE__  ": Channel %d pc_debug %d\n",
           Channel, pc_debug);
  }
#endif

  register_pcmcia_driver(&dev_info, &mc2_attach, &mc2_detach);

  return 0;
}

static void __exit mc2_cleanup(void)
{
  DEBUG(1, "wl24n_cs: unloading\n");
  mc2_flush_stale_links();
  if (dev_list != NULL)
    printk(KERN_DEBUG "wl24n_cs: devices remained on cleanup - "
           "time for reboot !\n");

  wl24n_remove_procdir();

  unregister_pcmcia_driver(&dev_info);
}

/* == PROC wl24n_cs_close ==
   called in wl24n_close, when the netdev got closed.
   checks if there is a link with this private data in the dev_list's mc2_priv.
   If not, return -ENODEV.
   Otherwise check if a release is pending (link->state & STALE_CONFIG)
   and trigger a timer for it. */
int wl24n_cs_close(void *priv)
{
  dev_link_t *link;

  /* Check if the device is in dev_list */
  for (link = dev_list; link != NULL; link = link->next)
    if (((local_info_t *)link->priv)->mc2_priv == priv)
      break;
  if (link == NULL)
    return -ENODEV;

  if (link->state & DEV_STALE_CONFIG) {
    link->release.expires = RUN_AT(HZ/20);
    link->state |= DEV_RELEASE_PENDING;
    add_timer(&link->release);
  }
    
  return 0;
} /* wl24n_cs_close */

module_init(mc2_init);
module_exit(mc2_cleanup);






