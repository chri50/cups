/*
 * "$Id: dirsvc.h 10415 2012-04-16 23:26:18Z mike $"
 *
 *   Directory services definitions for the CUPS scheduler.
 *
 *   Copyright 2007-2012 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products, all rights reserved.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 */

/*
 * Browse protocols...
 */

#define BROWSE_CUPS	1		/* CUPS */
#define	BROWSE_SLP	2		/* SLPv2 */
#define BROWSE_LDAP	4		/* LDAP */
#define BROWSE_DNSSD	8		/* DNS Service Discovery (aka Bonjour) */
#define BROWSE_SMB	16		/* SMB/Samba */
#define BROWSE_LPD	32		/* LPD via xinetd or launchd */
#define BROWSE_ALL	63		/* All protocols */


/*
 * Browse address...
 */

typedef struct
{
  char			iface[32];	/* Destination interface */
  http_addr_t		to;		/* Destination address */
} cupsd_dirsvc_addr_t;


/*
 * Relay structure...
 */

typedef struct
{
  cups_array_t		*from;		/* Source address/name mask(s) */
  http_addr_t		to;		/* Destination address */
} cupsd_dirsvc_relay_t;


/*
 * Polling structure...
 */

typedef struct
{
  char			hostname[64];	/* Hostname (actually, IP address) */
  int			port;		/* Port number */
  int			pid;		/* Current poll server PID */
} cupsd_dirsvc_poll_t;


/*
 * Globals...
 */

VAR int			Browsing	VALUE(TRUE),
					/* Whether or not browsing is enabled */
			BrowseWebIF	VALUE(FALSE),
					/* Whether the web interface is advertised */
			BrowseLocalProtocols
					VALUE(BROWSE_ALL),
					/* Protocols to support for local printers */
			BrowseRemoteProtocols
					VALUE(BROWSE_ALL),
					/* Protocols to support for remote printers */
			BrowseShortNames VALUE(TRUE),
					/* Short names for remote printers? */
			BrowseSocket	VALUE(-1),
					/* Socket for browsing */
			BrowsePort	VALUE(IPP_PORT),
					/* Port number for broadcasts */
			BrowseInterval	VALUE(DEFAULT_INTERVAL),
					/* Broadcast interval in seconds */
			BrowseTimeout	VALUE(DEFAULT_TIMEOUT),
					/* Time out for printers in seconds */
			UseNetworkDefault VALUE(CUPS_DEFAULT_USE_NETWORK_DEFAULT),
					/* Use the network default printer? */
			NumBrowsers	VALUE(0);
					/* Number of broadcast addresses */
VAR char		*BrowseLocalOptions
					VALUE(NULL),
					/* Options to add to local printer URIs */
			*BrowseRemoteOptions
					VALUE(NULL);
					/* Options to add to remote printer URIs */
VAR cupsd_dirsvc_addr_t	*Browsers	VALUE(NULL);
					/* Broadcast addresses */
VAR cupsd_location_t	*BrowseACL	VALUE(NULL);
					/* Browser access control list */
VAR cupsd_printer_t	*BrowseNext	VALUE(NULL);
					/* Next class/printer to broadcast */
VAR int			NumRelays	VALUE(0);
					/* Number of broadcast relays */
VAR cupsd_dirsvc_relay_t *Relays	VALUE(NULL);
					/* Broadcast relays */
VAR int			NumPolled	VALUE(0);
					/* Number of polled servers */
VAR cupsd_dirsvc_poll_t	*Polled		VALUE(NULL);
					/* Polled servers */
VAR int			PollPipe	VALUE(0);
					/* Status pipe for pollers */
VAR cupsd_statbuf_t	*PollStatusBuffer VALUE(NULL);
					/* Status buffer for pollers */

#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
VAR char		*DNSSDComputerName VALUE(NULL),
					/* Computer/server name */
			*DNSSDHostName	VALUE(NULL),
					/* Hostname */
			*DNSSDSubTypes VALUE(NULL);
					/* Bonjour registration subtypes */
VAR cups_array_t	*DNSSDAlias	VALUE(NULL);
					/* List of dynamic ServerAlias's */
VAR int			DNSSDPort	VALUE(0);
					/* Port number to register */
VAR cups_array_t	*DNSSDPrinters	VALUE(NULL);
					/* Printers we have registered */
#  ifdef HAVE_DNSSD
VAR DNSServiceRef	DNSSDMaster	VALUE(NULL);
					/* Master DNS-SD service reference */
#  else /* HAVE_AVAHI */
VAR AvahiThreadedPoll	*DNSSDMaster	VALUE(NULL);
					/* Master polling interface for Avahi */
VAR AvahiClient		*DNSSDClient	VALUE(NULL);
					/* Client information */
#  endif /* HAVE_DNSSD */
VAR cupsd_srv_t		WebIFSrv	VALUE(NULL);
					/* Service reference for the web interface */
#endif /* HAVE_DNSSD || HAVE_AVAHI */

VAR char		*LPDConfigFile	VALUE(NULL),
					/* LPD configuration file */
			*SMBConfigFile	VALUE(NULL);
					/* SMB configuration file */


/*
 * Prototypes...
 */

extern void	cupsdDeregisterPrinter(cupsd_printer_t *p, int removeit);
extern void	cupsdLoadRemoteCache(void);
extern void	cupsdRegisterPrinter(cupsd_printer_t *p);
extern void	cupsdRestartPolling(void);
extern void	cupsdSaveRemoteCache(void);
extern void	cupsdSendBrowseList(void);
extern void	cupsdStartBrowsing(void);
extern void	cupsdStartPolling(void);
extern void	cupsdStopBrowsing(void);
extern void	cupsdStopPolling(void);
#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
extern void	cupsdUpdateDNSSDName(void);
#endif /* HAVE_DNSSD || HAVE_AVAHI */


/*
 * End of "$Id: dirsvc.h 10415 2012-04-16 23:26:18Z mike $".
 */
