/*
 * "$Id: dirsvc.c 10472 2012-05-18 02:25:18Z mike $"
 *
 *   Directory services routines for the CUPS scheduler.
 *
 *   Copyright 2007-2012 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products, all rights reserved.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 *
 * Contents:
 *
 *   cupsdDeregisterPrinter()  - Stop sending broadcast information for a local
 *				 printer and remove any pending references to
 *				 remote printers.
 *   cupsdLoadRemoteCache()    - Load the remote printer cache.
 *   cupsdRegisterPrinter()    - Start sending broadcast information for a
 *				 printer or update the broadcast contents.
 *   cupsdRestartPolling()     - Restart polling servers as needed.
 *   cupsdSaveRemoteCache()    - Save the remote printer cache.
 *   cupsdSendBrowseList()     - Send new browsing information as necessary.
 *   cupsdStartBrowsing()      - Start sending and receiving broadcast
 *				 information.
 *   cupsdStartPolling()       - Start polling servers as needed.
 *   cupsdStopBrowsing()       - Stop sending and receiving broadcast
 *				 information.
 *   cupsdStopPolling()        - Stop polling servers as needed.
 *   cupsdUpdateDNSSDName()    - Update the computer name we use for
 *				 browsing...
 *   dequote()                 - Remote quotes from a string.
 *   dnssdAddAlias()	       - Add a DNS-SD alias name.
 *   dnssdBuildTxtRecord()     - Build a TXT record from printer info.
 *   dnssdComparePrinters()    - Compare the registered names of two printers.
 *   dnssdDeregisterInstance() - Deregister a DNS-SD service instance.
 *   dnssdDeregisterPrinter()  - Deregister all services for a printer.
 *   dnssdErrorString()        - Return an error string for an error code.
 *   dnssdRegisterCallback()   - Free a TXT record.
 *   dnssdRegisterCallback()   - DNSServiceRegister callback.
 *   dnssdRegisterInstance()   - Register an instance of a printer service.
 *   dnssdRegisterPrinter()    - Start sending broadcast information for a
 *				 printer or update the broadcast contents.
 *   dnssdStop()	       - Stop all DNS-SD registrations.
 *   dnssdUpdate()	       - Handle DNS-SD queries.
 *   get_auth_info_required()  - Get the auth-info-required value to advertise.
 *   get_hostconfig()	       - Get an /etc/hostconfig service setting.
 *   is_local_queue()          - Determine whether the URI points at a local
 *                               queue.
 *   process_browse_data()     - Process new browse data.
 *   process_implicit_classes()- Create/update implicit classes as needed.
 *   send_cups_browse()        - Send new browsing information using the CUPS
 *                               protocol.
 *   update_cups_browse()      - Update the browse lists using the CUPS
 *                               protocol.
 *   update_lpd()	       - Update the LPD configuration as needed.
 *   update_polling()	       - Read status messages from the poll daemons.
 *   update_smb()	       - Update the SMB configuration as needed.
 */

/*
 * Include necessary headers...
 */

#include "cupsd.h"
#include <grp.h>

#if defined(HAVE_DNSSD) && defined(__APPLE__)
#  include <nameser.h>
#  include <CoreFoundation/CoreFoundation.h>
#  include <SystemConfiguration/SystemConfiguration.h>
#endif /* HAVE_DNSSD && __APPLE__ */


/*
 * Local functions...
 */

static char	*dequote(char *d, const char *s, int dlen);
static char	*get_auth_info_required(cupsd_printer_t *p,
			                        char *buffer, size_t bufsize);
#ifdef __APPLE__
static int	get_hostconfig(const char *name);
#endif /* __APPLE__ */
static int	is_local_queue(const char *uri, char *host, int hostlen,
		               char *resource, int resourcelen);
static void	process_browse_data(const char *uri, const char *host,
		                    const char *resource, cups_ptype_t type,
				    ipp_pstate_t state, const char *location,
				    const char *info, const char *make_model,
				    int num_attrs, cups_option_t *attrs);
static void	process_implicit_classes(void);
static void	send_cups_browse(cupsd_printer_t *p);
static void	update_cups_browse(void);
static void	update_lpd(int onoff);
static void	update_polling(void);
static void	update_smb(int onoff);


#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
#  ifdef __APPLE__
static void		dnssdAddAlias(const void *key, const void *value,
			              void *context);
#  endif /* __APPLE__ */
static cupsd_txt_t	dnssdBuildTxtRecord(cupsd_printer_t *p, int for_lpd);
static int		dnssdComparePrinters(cupsd_printer_t *a, cupsd_printer_t *b);
static void		dnssdDeregisterInstance(cupsd_srv_t *srv);
static void		dnssdDeregisterPrinter(cupsd_printer_t *p,
			                       int clear_name);
static const char	*dnssdErrorString(int error);
static void		dnssdFreeTxtRecord(cupsd_txt_t *txt);
#  ifdef HAVE_DNSSD
static void		dnssdRegisterCallback(DNSServiceRef sdRef,
					      DNSServiceFlags flags,
					      DNSServiceErrorType errorCode,
					      const char *name,
					      const char *regtype,
					      const char *domain,
					      void *context);
#  else
static void		dnssdRegisterCallback(AvahiEntryGroup *p,
					      AvahiEntryGroupState state,
					      void *context);
#  endif /* HAVE_DNSSD */
static int		dnssdRegisterInstance(cupsd_srv_t *srv,
					      cupsd_printer_t *p,
					      char *name, const char *type,
					      const char *subtypes, int port,
					      cupsd_txt_t *txt, int commit);
static void		dnssdRegisterPrinter(cupsd_printer_t *p);
static void		dnssdStop(void);
#  ifdef HAVE_DNSSD
static void		dnssdUpdate(void);
#  endif /* HAVE_DNSSD */
#endif /* HAVE_DNSSD || HAVE_AVAHI */


/*
 * 'cupsdDeregisterPrinter()' - Stop sending broadcast information for a
 *				local printer and remove any pending
 *                              references to remote printers.
 */

void
cupsdDeregisterPrinter(
    cupsd_printer_t *p,			/* I - Printer to register */
    int             removeit)		/* I - Printer being permanently removed */
{
 /*
  * Only deregister if browsing is enabled and it's a local printer...
  */

  cupsdLogMessage(CUPSD_LOG_DEBUG,
                  "cupsdDeregisterPrinter(p=%p(%s), removeit=%d)", p, p->name,
		  removeit);

  if (!Browsing || !p->shared ||
      (p->type & (CUPS_PRINTER_REMOTE | CUPS_PRINTER_IMPLICIT |
                  CUPS_PRINTER_SCANNER)))
    return;

 /*
  * Announce the deletion...
  */

  if ((BrowseLocalProtocols & BROWSE_CUPS) && BrowseSocket >= 0)
  {
    cups_ptype_t savedtype = p->type;	/* Saved printer type */

    p->type |= CUPS_PRINTER_DELETE;

    send_cups_browse(p);

    p->type = savedtype;
  }

#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
  if (removeit && (BrowseLocalProtocols & BROWSE_DNSSD) && DNSSDMaster)
    dnssdDeregisterPrinter(p, 1);
#endif /* HAVE_DNSSD || HAVE_AVAHI */
}


/*
 * 'cupsdLoadRemoteCache()' - Load the remote printer cache.
 */

void
cupsdLoadRemoteCache(void)
{
  int			i;		/* Looping var */
  cups_file_t		*fp;		/* remote.cache file */
  int			linenum;	/* Current line number */
  char			line[4096],	/* Line from file */
			*value,		/* Pointer to value */
			*valueptr,	/* Pointer into value */
			scheme[32],	/* Scheme portion of URI */
			username[64],	/* Username portion of URI */
			host[HTTP_MAX_HOST],
					/* Hostname portion of URI */
			resource[HTTP_MAX_URI];
					/* Resource portion of URI */
  int			port;		/* Port number */
  cupsd_printer_t	*p;		/* Current printer */
  time_t		now;		/* Current time */


 /*
  * Don't load the cache if the remote protocols are disabled...
  */

  if (!Browsing)
  {
    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "cupsdLoadRemoteCache: Not loading remote cache.");
    return;
  }

 /*
  * Open the remote.cache file...
  */

  snprintf(line, sizeof(line), "%s/remote.cache", CacheDir);
  if ((fp = cupsdOpenConfFile(line)) == NULL)
    return;

 /*
  * Read printer configurations until we hit EOF...
  */

  linenum = 0;
  p       = NULL;
  now     = time(NULL);

  while (cupsFileGetConf(fp, line, sizeof(line), &value, &linenum))
  {
   /*
    * Decode the directive...
    */

    if (!_cups_strcasecmp(line, "<Printer") ||
        !_cups_strcasecmp(line, "<DefaultPrinter"))
    {
     /*
      * <Printer name> or <DefaultPrinter name>
      */

      if (p == NULL && value)
      {
       /*
        * Add the printer and a base file type...
	*/

        cupsdLogMessage(CUPSD_LOG_DEBUG,
	                "cupsdLoadRemoteCache: Loading printer %s...", value);

        if ((p = cupsdFindDest(value)) != NULL)
	{
	  if (p->type & CUPS_PRINTER_CLASS)
	  {
	    cupsdLogMessage(CUPSD_LOG_WARN,
	                    "Cached remote printer \"%s\" conflicts with "
			    "existing class!",
	                    value);
	    p = NULL;
	    continue;
	  }
	}
	else
          p = cupsdAddPrinter(value);

	p->accepting     = 1;
	p->state         = IPP_PRINTER_IDLE;
	p->type          |= CUPS_PRINTER_REMOTE | CUPS_PRINTER_DISCOVERED;
	p->browse_time   = now;
	p->browse_expire = now + BrowseTimeout;

       /*
        * Set the default printer as needed...
	*/

        if (!_cups_strcasecmp(line, "<DefaultPrinter"))
	  DefaultPrinter = p;
      }
      else
      {
        cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
        break;
      }
    }
    else if (!_cups_strcasecmp(line, "<Class") ||
             !_cups_strcasecmp(line, "<DefaultClass"))
    {
     /*
      * <Class name> or <DefaultClass name>
      */

      if (p == NULL && value)
      {
       /*
        * Add the printer and a base file type...
	*/

        cupsdLogMessage(CUPSD_LOG_DEBUG,
	                "cupsdLoadRemoteCache: Loading class %s...", value);

        if ((p = cupsdFindDest(value)) != NULL)
	  p->type = CUPS_PRINTER_CLASS;
	else
          p = cupsdAddClass(value);

	p->accepting     = 1;
	p->state         = IPP_PRINTER_IDLE;
	p->type          |= CUPS_PRINTER_REMOTE | CUPS_PRINTER_DISCOVERED;
	p->browse_time   = now;
	p->browse_expire = now + BrowseTimeout;

       /*
        * Set the default printer as needed...
	*/

        if (!_cups_strcasecmp(line, "<DefaultClass"))
	  DefaultPrinter = p;
      }
      else
      {
        cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
        break;
      }
    }
    else if (!_cups_strcasecmp(line, "</Printer>") ||
             !_cups_strcasecmp(line, "</Class>"))
    {
      if (p != NULL)
      {
       /*
        * Close out the current printer...
	*/

        cupsdSetPrinterAttrs(p);

        p = NULL;
      }
      else
        cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!p)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "UUID"))
    {
      if (value && !strncmp(value, "urn:uuid:", 9))
        cupsdSetString(&(p->uuid), value);
      else
        cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Bad UUID on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "Info"))
    {
      if (value)
	cupsdSetString(&p->info, value);
    }
    else if (!_cups_strcasecmp(line, "MakeModel"))
    {
      if (value)
	cupsdSetString(&p->make_model, value);
    }
    else if (!_cups_strcasecmp(line, "Location"))
    {
      if (value)
	cupsdSetString(&p->location, value);
    }
    else if (!_cups_strcasecmp(line, "DeviceURI"))
    {
      if (value)
      {
	httpSeparateURI(HTTP_URI_CODING_ALL, value, scheme, sizeof(scheme),
	                username, sizeof(username), host, sizeof(host), &port,
			resource, sizeof(resource));

	cupsdSetString(&p->hostname, host);
	cupsdSetString(&p->uri, value);
	cupsdSetDeviceURI(p, value);
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "Option") && value)
    {
     /*
      * Option name value
      */

      for (valueptr = value; *valueptr && !isspace(*valueptr & 255); valueptr ++);

      if (!*valueptr)
        cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
      else
      {
        for (; *valueptr && isspace(*valueptr & 255); *valueptr++ = '\0');

        p->num_options = cupsAddOption(value, valueptr, p->num_options,
	                               &(p->options));
      }
    }
    else if (!_cups_strcasecmp(line, "Reason"))
    {
      if (value)
      {
        for (i = 0 ; i < p->num_reasons; i ++)
	  if (!strcmp(value, p->reasons[i]))
	    break;

        if (i >= p->num_reasons &&
	    p->num_reasons < (int)(sizeof(p->reasons) / sizeof(p->reasons[0])))
	{
	  p->reasons[p->num_reasons] = _cupsStrAlloc(value);
	  p->num_reasons ++;
	}
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "State"))
    {
     /*
      * Set the initial queue state...
      */

      if (value && !_cups_strcasecmp(value, "idle"))
        p->state = IPP_PRINTER_IDLE;
      else if (value && !_cups_strcasecmp(value, "stopped"))
      {
        p->state = IPP_PRINTER_STOPPED;
	cupsdSetPrinterReasons(p, "+paused");
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "StateMessage"))
    {
     /*
      * Set the initial queue state message...
      */

      if (value)
	strlcpy(p->state_message, value, sizeof(p->state_message));
    }
    else if (!_cups_strcasecmp(line, "Accepting"))
    {
     /*
      * Set the initial accepting state...
      */

      if (value &&
          (!_cups_strcasecmp(value, "yes") ||
           !_cups_strcasecmp(value, "on") ||
           !_cups_strcasecmp(value, "true")))
        p->accepting = 1;
      else if (value &&
               (!_cups_strcasecmp(value, "no") ||
        	!_cups_strcasecmp(value, "off") ||
        	!_cups_strcasecmp(value, "false")))
        p->accepting = 0;
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "Type"))
    {
      if (value)
        p->type = atoi(value);
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "BrowseTime"))
    {
      if (value)
      {
        time_t t = atoi(value);

	if (t > p->browse_expire)
          p->browse_expire = t;
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "JobSheets"))
    {
     /*
      * Set the initial job sheets...
      */

      if (value)
      {
	for (valueptr = value; *valueptr && !isspace(*valueptr & 255); valueptr ++);

	if (*valueptr)
          *valueptr++ = '\0';

	cupsdSetString(&p->job_sheets[0], value);

	while (isspace(*valueptr & 255))
          valueptr ++;

	if (*valueptr)
	{
          for (value = valueptr; *valueptr && !isspace(*valueptr & 255); valueptr ++);

	  if (*valueptr)
            *valueptr = '\0';

	  cupsdSetString(&p->job_sheets[1], value);
	}
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "AllowUser"))
    {
      if (value)
      {
        p->deny_users = 0;
        cupsdAddString(&(p->users), value);
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else if (!_cups_strcasecmp(line, "DenyUser"))
    {
      if (value)
      {
        p->deny_users = 1;
        cupsdAddString(&(p->users), value);
      }
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "Syntax error on line %d of remote.cache.", linenum);
    }
    else
    {
     /*
      * Something else we don't understand...
      */

      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "Unknown configuration directive %s on line %d of remote.cache.",
	              line, linenum);
    }
  }

  cupsFileClose(fp);

 /*
  * Do auto-classing if needed...
  */

  process_implicit_classes();
}


/*
 * 'cupsdRegisterPrinter()' - Start sending broadcast information for a
 *                            printer or update the broadcast contents.
 */

void
cupsdRegisterPrinter(cupsd_printer_t *p)/* I - Printer */
{
  cupsdLogMessage(CUPSD_LOG_DEBUG, "cupsdRegisterPrinter(p=%p(%s))", p,
                  p->name);

  if (!Browsing || !BrowseLocalProtocols ||
      (p->type & (CUPS_PRINTER_REMOTE | CUPS_PRINTER_IMPLICIT |
                  CUPS_PRINTER_SCANNER)))
    return;

#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
  if ((BrowseLocalProtocols & BROWSE_DNSSD) && DNSSDMaster)
    dnssdRegisterPrinter(p);
#endif /* HAVE_DNSSD || HAVE_AVAHI */
}


/*
 * 'cupsdRestartPolling()' - Restart polling servers as needed.
 */

void
cupsdRestartPolling(void)
{
  int			i;		/* Looping var */
  cupsd_dirsvc_poll_t	*pollp;		/* Current polling server */


  for (i = 0, pollp = Polled; i < NumPolled; i ++, pollp ++)
    if (pollp->pid)
      kill(pollp->pid, SIGHUP);
}


/*
 * 'cupsdSaveRemoteCache()' - Save the remote printer cache.
 */

void
cupsdSaveRemoteCache(void)
{
  int			i;		/* Looping var */
  cups_file_t		*fp;		/* remote.cache file */
  char			filename[1024],	/* remote.cache filename */
			temp[1024],	/* Temporary string */
			value[2048],	/* Value string */
			*name;		/* Current user name */
  cupsd_printer_t	*printer;	/* Current printer class */
  time_t		curtime;	/* Current time */
  struct tm		*curdate;	/* Current date */
  cups_option_t		*option;	/* Current option */


 /*
  * Create the remote.cache file...
  */

  snprintf(filename, sizeof(filename), "%s/remote.cache", CacheDir);

  if ((fp = cupsdCreateConfFile(filename, ConfigFilePerm)) == NULL)
    return;

  cupsdLogMessage(CUPSD_LOG_DEBUG, "Saving remote.cache...");

 /*
  * Write a small header to the file...
  */

  curtime = time(NULL);
  curdate = localtime(&curtime);
  strftime(temp, sizeof(temp) - 1, "%Y-%m-%d %H:%M", curdate);

  cupsFilePuts(fp, "# Remote cache file for " CUPS_SVERSION "\n");
  cupsFilePrintf(fp, "# Written by cupsd on %s\n", temp);

 /*
  * Write each local printer known to the system...
  */

  for (printer = (cupsd_printer_t *)cupsArrayFirst(Printers);
       printer;
       printer = (cupsd_printer_t *)cupsArrayNext(Printers))
  {
   /*
    * Skip local destinations...
    */

    if (!(printer->type & CUPS_PRINTER_DISCOVERED))
      continue;

   /*
    * Write printers as needed...
    */

    if (printer == DefaultPrinter)
      cupsFilePuts(fp, "<Default");
    else
      cupsFilePutChar(fp, '<');

    if (printer->type & CUPS_PRINTER_CLASS)
      cupsFilePrintf(fp, "Class %s>\n", printer->name);
    else
      cupsFilePrintf(fp, "Printer %s>\n", printer->name);

    cupsFilePrintf(fp, "BrowseTime %d\n", (int)printer->browse_expire);

    cupsFilePrintf(fp, "UUID %s\n", printer->uuid);

    if (printer->info)
      cupsFilePutConf(fp, "Info", printer->info);

    if (printer->location)
      cupsFilePutConf(fp, "Location", printer->location);

    if (printer->make_model)
      cupsFilePutConf(fp, "MakeModel", printer->make_model);

    cupsFilePutConf(fp, "DeviceURI", printer->device_uri);

    if (printer->state == IPP_PRINTER_STOPPED)
      cupsFilePuts(fp, "State Stopped\n");
    else
      cupsFilePuts(fp, "State Idle\n");

    for (i = 0; i < printer->num_reasons; i ++)
      cupsFilePutConf(fp, "Reason", printer->reasons[i]);

    cupsFilePrintf(fp, "Type %d\n", printer->type);

    if (printer->accepting)
      cupsFilePuts(fp, "Accepting Yes\n");
    else
      cupsFilePuts(fp, "Accepting No\n");

    snprintf(value, sizeof(value), "%s %s", printer->job_sheets[0],
             printer->job_sheets[1]);
    cupsFilePutConf(fp, "JobSheets", value);

    for (name = (char *)cupsArrayFirst(printer->users);
	 name;
	 name = (char *)cupsArrayNext(printer->users))
      cupsFilePutConf(fp, printer->deny_users ? "DenyUser" : "AllowUser", name);

    for (i = printer->num_options, option = printer->options;
         i > 0;
	 i --, option ++)
    {
      snprintf(value, sizeof(value), "%s %s", option->name, option->value);
      cupsFilePutConf(fp, "Option", value);
    }

    if (printer->type & CUPS_PRINTER_CLASS)
      cupsFilePuts(fp, "</Class>\n");
    else
      cupsFilePuts(fp, "</Printer>\n");
  }

  cupsdCloseCreatedConfFile(fp, filename);
}


/*
 * 'cupsdSendBrowseList()' - Send new browsing information as necessary.
 */

void
cupsdSendBrowseList(void)
{
  int			count;		/* Number of dests to update */
  cupsd_printer_t	*p;		/* Current printer */
  time_t		ut,		/* Minimum update time */
			to;		/* Timeout time */


  if (!Browsing || !Printers)
    return;

 /*
  * Compute the update and timeout times...
  */

  to = time(NULL);
  ut = to - BrowseInterval;

 /*
  * Figure out how many printers need an update...
  */

  if (BrowseInterval > 0 && BrowseLocalProtocols)
  {
    int	max_count;			/* Maximum number to update */


   /*
    * Throttle the number of printers we'll be updating this time
    * around based on the number of queues that need updating and
    * the maximum number of queues to update each second...
    */

    max_count = 2 * cupsArrayCount(Printers) / BrowseInterval + 1;

    for (count = 0, p = (cupsd_printer_t *)cupsArrayFirst(Printers);
         count < max_count && p != NULL;
	 p = (cupsd_printer_t *)cupsArrayNext(Printers))
      if (!(p->type & (CUPS_PRINTER_REMOTE | CUPS_PRINTER_IMPLICIT |
                       CUPS_PRINTER_SCANNER)) &&
          p->shared && p->browse_time < ut)
        count ++;

   /*
    * Loop through all of the printers and send local updates as needed...
    */

    if (BrowseNext)
      p = (cupsd_printer_t *)cupsArrayFind(Printers, BrowseNext);
    else
      p = (cupsd_printer_t *)cupsArrayFirst(Printers);

    for (;
         count > 0;
	 p = (cupsd_printer_t *)cupsArrayNext(Printers))
    {
     /*
      * Check for wraparound...
      */

      if (!p)
        p = (cupsd_printer_t *)cupsArrayFirst(Printers);

      if (!p)
        break;
      else if ((p->type & (CUPS_PRINTER_REMOTE | CUPS_PRINTER_IMPLICIT |
                           CUPS_PRINTER_SCANNER)) ||
               !p->shared)
        continue;
      else if (p->browse_time < ut)
      {
       /*
	* Need to send an update...
	*/

	count --;

	p->browse_time = time(NULL);

	if ((BrowseLocalProtocols & BROWSE_CUPS) && BrowseSocket >= 0)
          send_cups_browse(p);
      }
    }

   /*
    * Save where we left off so that all printers get updated...
    */

    BrowseNext = p;
  }

 /*
  * Loop through all of the printers and timeout old printers as needed...
  */

  for (p = (cupsd_printer_t *)cupsArrayFirst(Printers);
       p;
       p = (cupsd_printer_t *)cupsArrayNext(Printers))
  {
   /*
    * If this is a remote queue, see if it needs to be timed out...
    */

    if ((p->type & CUPS_PRINTER_DISCOVERED) &&
        !(p->type & CUPS_PRINTER_IMPLICIT) &&
	p->browse_expire < to)
    {
      cupsdAddEvent(CUPSD_EVENT_PRINTER_DELETED, p, NULL,
		    "%s \'%s\' deleted by directory services (timeout).",
		    (p->type & CUPS_PRINTER_CLASS) ? "Class" : "Printer",
		    p->name);

      cupsdLogMessage(CUPSD_LOG_DEBUG,
		      "Remote destination \"%s\" has timed out; "
		      "deleting it...",
		      p->name);

      cupsArraySave(Printers);
      cupsdDeletePrinter(p, 1);
      cupsArrayRestore(Printers);
      cupsdMarkDirty(CUPSD_DIRTY_PRINTCAP | CUPSD_DIRTY_REMOTE);
    }
  }
}


/*
 * 'cupsdStartBrowsing()' - Start sending and receiving broadcast information.
 */

void
cupsdStartBrowsing(void)
{
  int			val;		/* Socket option value */
  struct sockaddr_in	addr;		/* Broadcast address */
  cupsd_printer_t	*p;		/* Current printer */


  BrowseNext = NULL;

  if (!Browsing || !(BrowseLocalProtocols | BrowseRemoteProtocols))
    return;

  if ((BrowseLocalProtocols | BrowseRemoteProtocols) & BROWSE_CUPS)
  {
    if (BrowseSocket < 0)
    {
     /*
      * Create the broadcast socket...
      */

      if ((BrowseSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      {
	cupsdLogMessage(CUPSD_LOG_ERROR,
			"Unable to create broadcast socket - %s.",
			strerror(errno));
	BrowseLocalProtocols &= ~BROWSE_CUPS;
	BrowseRemoteProtocols &= ~BROWSE_CUPS;

	if (FatalErrors & CUPSD_FATAL_BROWSE)
	  cupsdEndProcess(getpid(), 0);
      }
    }

    if (BrowseSocket >= 0)
    {
     /*
      * Bind the socket to browse port...
      */

      memset(&addr, 0, sizeof(addr));
      addr.sin_addr.s_addr = htonl(INADDR_ANY);
      addr.sin_family      = AF_INET;
      addr.sin_port        = htons(BrowsePort);

      if (bind(BrowseSocket, (struct sockaddr *)&addr, sizeof(addr)))
      {
	cupsdLogMessage(CUPSD_LOG_ERROR,
			"Unable to bind broadcast socket - %s.",
			strerror(errno));

#ifdef WIN32
	closesocket(BrowseSocket);
#else
	close(BrowseSocket);
#endif /* WIN32 */

	BrowseSocket = -1;
	BrowseLocalProtocols &= ~BROWSE_CUPS;
	BrowseRemoteProtocols &= ~BROWSE_CUPS;

	if (FatalErrors & CUPSD_FATAL_BROWSE)
	  cupsdEndProcess(getpid(), 0);
      }
    }

    if (BrowseSocket >= 0)
    {
     /*
      * Set the "broadcast" flag...
      */

      val = 1;
      if (setsockopt(BrowseSocket, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val)))
      {
	cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to set broadcast mode - %s.",
			strerror(errno));

#ifdef WIN32
	closesocket(BrowseSocket);
#else
	close(BrowseSocket);
#endif /* WIN32 */

	BrowseSocket = -1;
	BrowseLocalProtocols &= ~BROWSE_CUPS;
	BrowseRemoteProtocols &= ~BROWSE_CUPS;

	if (FatalErrors & CUPSD_FATAL_BROWSE)
	  cupsdEndProcess(getpid(), 0);
      }
    }

    if (BrowseSocket >= 0)
    {
     /*
      * Close the socket on exec...
      */

      fcntl(BrowseSocket, F_SETFD, fcntl(BrowseSocket, F_GETFD) | FD_CLOEXEC);

     /*
      * Finally, add the socket to the input selection set as needed...
      */

      if (BrowseRemoteProtocols & BROWSE_CUPS)
      {
       /*
	* We only listen if we want remote printers...
	*/

	cupsdAddSelect(BrowseSocket, (cupsd_selfunc_t)update_cups_browse,
		       NULL, NULL);
      }
    }
  }
  else
    BrowseSocket = -1;

#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
  if ((BrowseLocalProtocols | BrowseRemoteProtocols) & BROWSE_DNSSD)
  {
    cupsd_listener_t	*lis;		/* Current listening socket */
#  ifdef HAVE_DNSSD
    DNSServiceErrorType error;		/* Error from service creation */

   /*
    * First create a "master" connection for all registrations...
    */

    if ((error = DNSServiceCreateConnection(&DNSSDMaster))
	    != kDNSServiceErr_NoError)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
		      "Unable to create master DNS-SD reference: %d", error);

      if (FatalErrors & CUPSD_FATAL_BROWSE)
	cupsdEndProcess(getpid(), 0);
    }
    else
    {
     /*
      * Add the master connection to the select list...
      */

      int fd = DNSServiceRefSockFD(DNSSDMaster);

      fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

      cupsdAddSelect(fd, (cupsd_selfunc_t)dnssdUpdate, NULL, NULL);
    }

#  else /* HAVE_AVAHI */
    if ((DNSSDMaster = avahi_threaded_poll_new()) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to create DNS-SD thread.");

      if (FatalErrors & CUPSD_FATAL_BROWSE)
	cupsdEndProcess(getpid(), 0);
    }
    else
    {
      int error;			/* Error code, if any */

      DNSSDClient = avahi_client_new(avahi_threaded_poll_get(DNSSDMaster), 0,
                                     NULL, NULL, &error);

      if (DNSSDClient == NULL)
      {
        cupsdLogMessage(CUPSD_LOG_ERROR,
                        "Unable to communicate with avahi-daemon: %s",
                        dnssdErrorString(error));

        if (FatalErrors & CUPSD_FATAL_BROWSE)
	  cupsdEndProcess(getpid(), 0);

        avahi_threaded_poll_free(DNSSDMaster);
        DNSSDMaster = NULL;
      }
      else
	avahi_threaded_poll_start(DNSSDMaster);
    }
#  endif /* HAVE_DNSSD */

   /*
    * Then get the port we use for registrations.  If we are not listening
    * on any non-local ports, there is no sense sharing local printers via
    * Bonjour...
    */

    DNSSDPort = 0;

    for (lis = (cupsd_listener_t *)cupsArrayFirst(Listeners);
	 lis;
	 lis = (cupsd_listener_t *)cupsArrayNext(Listeners))
    {
      if (httpAddrLocalhost(&(lis->address)))
	continue;

      DNSSDPort = _httpAddrPort(&(lis->address));
      break;
    }

   /*
    * Create an array to track the printers we share...
    */

    if (BrowseRemoteProtocols & BROWSE_DNSSD)
      DNSSDPrinters = cupsArrayNew((cups_array_func_t)dnssdComparePrinters,
				   NULL);

   /*
    * Set the computer name and register the web interface...
    */

    cupsdUpdateDNSSDName();
  }
#endif /* HAVE_DNSSD || HAVE_AVAHI */

 /*
  * Enable LPD and SMB printer sharing as needed through external programs...
  */

  if (BrowseLocalProtocols & BROWSE_LPD)
    update_lpd(1);

  if (BrowseLocalProtocols & BROWSE_SMB)
    update_smb(1);

 /*
  * Register the individual printers
  */

  for (p = (cupsd_printer_t *)cupsArrayFirst(Printers);
       p;
       p = (cupsd_printer_t *)cupsArrayNext(Printers))
    if (!(p->type & (CUPS_PRINTER_REMOTE | CUPS_PRINTER_IMPLICIT |
                     CUPS_PRINTER_SCANNER)))
      cupsdRegisterPrinter(p);
}


/*
 * 'cupsdStartPolling()' - Start polling servers as needed.
 */

void
cupsdStartPolling(void)
{
  int			i;		/* Looping var */
  cupsd_dirsvc_poll_t	*pollp;		/* Current polling server */
  char			polld[1024];	/* Poll daemon path */
  char			sport[255];	/* Server port */
  char			bport[255];	/* Browser port */
  char			interval[255];	/* Poll interval */
  int			statusfds[2];	/* Status pipe */
  char			*argv[6];	/* Arguments */
  char			*envp[100];	/* Environment */


 /*
  * Don't do anything if we aren't polling...
  */

  if (NumPolled == 0 || BrowseSocket < 0)
  {
    PollPipe         = -1;
    PollStatusBuffer = NULL;
    return;
  }

 /*
  * Setup string arguments for polld, port and interval options.
  */

  snprintf(polld, sizeof(polld), "%s/daemon/cups-polld", ServerBin);

  sprintf(bport, "%d", BrowsePort);

  if (BrowseInterval)
    sprintf(interval, "%d", BrowseInterval);
  else
    strcpy(interval, "30");

  argv[0] = "cups-polld";
  argv[2] = sport;
  argv[3] = interval;
  argv[4] = bport;
  argv[5] = NULL;

  cupsdLoadEnv(envp, (int)(sizeof(envp) / sizeof(envp[0])));

 /*
  * Create a pipe that receives the status messages from each
  * polling daemon...
  */

  if (cupsdOpenPipe(statusfds))
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "Unable to create polling status pipes - %s.",
	            strerror(errno));
    PollPipe         = -1;
    PollStatusBuffer = NULL;
    return;
  }

  PollPipe         = statusfds[0];
  PollStatusBuffer = cupsdStatBufNew(PollPipe, "[Poll]");

 /*
  * Run each polling daemon, redirecting stderr to the polling pipe...
  */

  for (i = 0, pollp = Polled; i < NumPolled; i ++, pollp ++)
  {
    sprintf(sport, "%d", pollp->port);

    argv[1] = pollp->hostname;

    if (cupsdStartProcess(polld, argv, envp, -1, -1, statusfds[1], -1, -1,
                          0, DefaultProfile, NULL, &(pollp->pid)) < 0)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdStartPolling: Unable to fork polling daemon - %s",
                      strerror(errno));
      pollp->pid = 0;
      break;
    }
    else
      cupsdLogMessage(CUPSD_LOG_DEBUG,
                      "cupsdStartPolling: Started polling daemon for %s:%d, pid = %d",
                      pollp->hostname, pollp->port, pollp->pid);
  }

  close(statusfds[1]);

 /*
  * Finally, add the pipe to the input selection set...
  */

  cupsdAddSelect(PollPipe, (cupsd_selfunc_t)update_polling, NULL, NULL);
}


/*
 * 'cupsdStopBrowsing()' - Stop sending and receiving broadcast information.
 */

void
cupsdStopBrowsing(void)
{
  cupsd_printer_t	*p;		/* Current printer */


  if (!Browsing || !(BrowseLocalProtocols | BrowseRemoteProtocols))
    return;

 /*
  * De-register the individual printers
  */

  for (p = (cupsd_printer_t *)cupsArrayFirst(Printers);
       p;
       p = (cupsd_printer_t *)cupsArrayNext(Printers))
    if (!(p->type & (CUPS_PRINTER_REMOTE | CUPS_PRINTER_IMPLICIT |
                     CUPS_PRINTER_SCANNER)))
      cupsdDeregisterPrinter(p, 1);

 /*
  * Shut down browsing sockets...
  */

  if (((BrowseLocalProtocols | BrowseRemoteProtocols) & BROWSE_CUPS) &&
      BrowseSocket >= 0)
  {
   /*
    * Close the socket and remove it from the input selection set.
    */

#ifdef WIN32
    closesocket(BrowseSocket);
#else
    close(BrowseSocket);
#endif /* WIN32 */

    cupsdRemoveSelect(BrowseSocket);
    BrowseSocket = -1;
  }

#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
  if ((BrowseLocalProtocols & BROWSE_DNSSD) && DNSSDMaster)
    dnssdStop();
#endif /* HAVE_DNSSD || HAVE_AVAHI */

 /*
  * Disable LPD and SMB printer sharing as needed through external programs...
  */

  if (BrowseLocalProtocols & BROWSE_LPD)
    update_lpd(0);

  if (BrowseLocalProtocols & BROWSE_SMB)
    update_smb(0);
}


/*
 * 'cupsdStopPolling()' - Stop polling servers as needed.
 */

void
cupsdStopPolling(void)
{
  int			i;		/* Looping var */
  cupsd_dirsvc_poll_t	*pollp;		/* Current polling server */


  if (PollPipe >= 0)
  {
    cupsdStatBufDelete(PollStatusBuffer);
    close(PollPipe);

    cupsdRemoveSelect(PollPipe);

    PollPipe         = -1;
    PollStatusBuffer = NULL;
  }

  for (i = 0, pollp = Polled; i < NumPolled; i ++, pollp ++)
    if (pollp->pid)
      cupsdEndProcess(pollp->pid, 0);
}


#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
/*
 * 'cupsdUpdateDNSSDName()' - Update the computer name we use for browsing...
 */

void
cupsdUpdateDNSSDName(void)
{
  char		webif[1024];		/* Web interface share name */
#  ifdef __APPLE__
  SCDynamicStoreRef sc;			/* Context for dynamic store */
  CFDictionaryRef btmm;			/* Back-to-My-Mac domains */
  CFStringEncoding nameEncoding;	/* Encoding of computer name */
  CFStringRef	nameRef;		/* Host name CFString */
  char		nameBuffer[1024];	/* C-string buffer */
#  endif /* __APPLE__ */


 /*
  * Only share the web interface and printers when non-local listening is
  * enabled...
  */

  if (!DNSSDPort)
    return;

 /*
  * Get the computer name as a c-string...
  */

#  ifdef __APPLE__
  sc = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("cupsd"), NULL, NULL);

  if (sc)
  {
   /*
    * Get the computer name from the dynamic store...
    */

    cupsdClearString(&DNSSDComputerName);

    if ((nameRef = SCDynamicStoreCopyComputerName(sc, &nameEncoding)) != NULL)
    {
      if (CFStringGetCString(nameRef, nameBuffer, sizeof(nameBuffer),
			     kCFStringEncodingUTF8))
      {
        cupsdLogMessage(CUPSD_LOG_DEBUG,
	                "Dynamic store computer name is \"%s\".", nameBuffer);
	cupsdSetString(&DNSSDComputerName, nameBuffer);
      }

      CFRelease(nameRef);
    }

    if (!DNSSDComputerName)
    {
     /*
      * Use the ServerName instead...
      */

      cupsdLogMessage(CUPSD_LOG_DEBUG,
                      "Using ServerName \"%s\" as computer name.", ServerName);
      cupsdSetString(&DNSSDComputerName, ServerName);
    }

   /*
    * Get the local hostname from the dynamic store...
    */

    cupsdClearString(&DNSSDHostName);

    if ((nameRef = SCDynamicStoreCopyLocalHostName(sc)) != NULL)
    {
      if (CFStringGetCString(nameRef, nameBuffer, sizeof(nameBuffer),
			     kCFStringEncodingUTF8))
      {
        cupsdLogMessage(CUPSD_LOG_DEBUG,
	                "Dynamic store host name is \"%s\".", nameBuffer);
	cupsdSetString(&DNSSDHostName, nameBuffer);
      }

      CFRelease(nameRef);
    }

    if (!DNSSDHostName)
    {
     /*
      * Use the ServerName instead...
      */

      cupsdLogMessage(CUPSD_LOG_DEBUG,
                      "Using ServerName \"%s\" as host name.", ServerName);
      cupsdSetString(&DNSSDHostName, ServerName);
    }

   /*
    * Get any Back-to-My-Mac domains and add them as aliases...
    */

    cupsdFreeAliases(DNSSDAlias);
    DNSSDAlias = NULL;

    btmm = SCDynamicStoreCopyValue(sc, CFSTR("Setup:/Network/BackToMyMac"));
    if (btmm && CFGetTypeID(btmm) == CFDictionaryGetTypeID())
    {
      cupsdLogMessage(CUPSD_LOG_DEBUG, "%d Back to My Mac aliases to add.",
		      (int)CFDictionaryGetCount(btmm));
      CFDictionaryApplyFunction(btmm, dnssdAddAlias, NULL);
    }
    else if (btmm)
      cupsdLogMessage(CUPSD_LOG_ERROR,
		      "Bad Back to My Mac data in dynamic store!");
    else
      cupsdLogMessage(CUPSD_LOG_DEBUG, "No Back to My Mac aliases to add.");

    if (btmm)
      CFRelease(btmm);

    CFRelease(sc);
  }
  else
#  endif /* __APPLE__ */
#  ifdef HAVE_AVAHI
  if (DNSSDClient)
  {
    const char	*host_name = avahi_client_get_host_name(DNSSDClient);
    const char	*host_fqdn = avahi_client_get_host_name_fqdn(DNSSDClient);

    cupsdSetString(&DNSSDComputerName, host_name ? host_name : ServerName);

    if (host_fqdn)
      cupsdSetString(&DNSSDHostName, host_fqdn);
    else if (strchr(ServerName, '.'))
      cupsdSetString(&DNSSDHostName, ServerName);
    else
      cupsdSetStringf(&DNSSDHostName, "%s.local", ServerName);
  }
  else
#  endif /* HAVE_AVAHI */
  {
    cupsdSetString(&DNSSDComputerName, ServerName);

    if (strchr(ServerName, '.'))
      cupsdSetString(&DNSSDHostName, ServerName);
    else
      cupsdSetStringf(&DNSSDHostName, "%s.local", ServerName);
  }

 /*
  * Then (re)register the web interface if enabled...
  */

  if (BrowseWebIF)
  {
    if (DNSSDComputerName)
      snprintf(webif, sizeof(webif), "CUPS @ %s", DNSSDComputerName);
    else
      strlcpy(webif, "CUPS", sizeof(webif));

    dnssdDeregisterInstance(&WebIFSrv);
    dnssdRegisterInstance(&WebIFSrv, NULL, webif, "_http._tcp", "_printer",
                          DNSSDPort, NULL, 1);
  }
}
#endif /* HAVE_DNSSD || HAVE_AVAHI */


/*
 * 'dequote()' - Remote quotes from a string.
 */

static char *				/* O - Dequoted string */
dequote(char       *d,			/* I - Destination string */
        const char *s,			/* I - Source string */
	int        dlen)		/* I - Destination length */
{
  char	*dptr;				/* Pointer into destination */


  if (s)
  {
    for (dptr = d, dlen --; *s && dlen > 0; s ++)
      if (*s != '\"')
      {
	*dptr++ = *s;
	dlen --;
      }

    *dptr = '\0';
  }
  else
    *d = '\0';

  return (d);
}


#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
#  ifdef __APPLE__
/*
 * 'dnssdAddAlias()' - Add a DNS-SD alias name.
 */

static void
dnssdAddAlias(const void *key,		/* I - Key */
              const void *value,	/* I - Value (domain) */
	      void       *context)	/* I - Unused */
{
  char	valueStr[1024],			/* Domain string */
	hostname[1024],			/* Complete hostname */
	*hostptr;			/* Pointer into hostname */


  (void)key;
  (void)context;

  if (CFGetTypeID((CFStringRef)value) == CFStringGetTypeID() &&
      CFStringGetCString((CFStringRef)value, valueStr, sizeof(valueStr),
                         kCFStringEncodingUTF8))
  {
    snprintf(hostname, sizeof(hostname), "%s.%s", DNSSDHostName, valueStr);
    hostptr = hostname + strlen(hostname) - 1;
    if (*hostptr == '.')
      *hostptr = '\0';			/* Strip trailing dot */

    if (!DNSSDAlias)
      DNSSDAlias = cupsArrayNew(NULL, NULL);

    cupsdAddAlias(DNSSDAlias, hostname);
    cupsdLogMessage(CUPSD_LOG_DEBUG, "Added Back to My Mac ServerAlias %s",
		    hostname);
  }
  else
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "Bad Back to My Mac domain in dynamic store!");
}
#  endif /* __APPLE__ */


/*
 * 'dnssdBuildTxtRecord()' - Build a TXT record from printer info.
 */

static cupsd_txt_t			/* O - TXT record */
dnssdBuildTxtRecord(
    cupsd_printer_t *p,			/* I - Printer information */
    int             for_lpd)		/* I - 1 = LPD, 0 = IPP */
{
  int		i,			/* Looping var */
		count;			/* Count of key/value pairs */
  char		admin_hostname[256],	/* .local hostname for admin page */
		adminurl_str[256],	/* URL for the admin page */
		type_str[32],		/* Type to string buffer */
		state_str[32],		/* State to string buffer */
		rp_str[1024],		/* Queue name string buffer */
		air_str[1024],		/* auth-info-required string buffer */
		*keyvalue[32][2];	/* Table of key/value pairs */
  cupsd_txt_t	txt;			/* TXT record */


 /*
  * Load up the key value pairs...
  */

  count = 0;

  if (!for_lpd || (BrowseLocalProtocols & BROWSE_LPD))
  {
    keyvalue[count  ][0] = "txtvers";
    keyvalue[count++][1] = "1";

    keyvalue[count  ][0] = "qtotal";
    keyvalue[count++][1] = "1";

    keyvalue[count  ][0] = "rp";
    keyvalue[count++][1] = rp_str;
    if (for_lpd)
      strlcpy(rp_str, p->name, sizeof(rp_str));
    else
      snprintf(rp_str, sizeof(rp_str), "%s/%s",
	       (p->type & CUPS_PRINTER_CLASS) ? "classes" : "printers",
	       p->name);

    keyvalue[count  ][0] = "ty";
    keyvalue[count++][1] = p->make_model ? p->make_model : "Unknown";

    if (strstr(DNSSDHostName, ".local"))
      strlcpy(admin_hostname, DNSSDHostName, sizeof(admin_hostname));
    else
      snprintf(admin_hostname, sizeof(admin_hostname), "%s.local.",
               DNSSDHostName);
    httpAssembleURIf(HTTP_URI_CODING_ALL, adminurl_str, sizeof(adminurl_str),
#  ifdef HAVE_SSL
		     "https",
#  else
		     "http",
#  endif /* HAVE_SSL */
		     NULL, admin_hostname, DNSSDPort, "/%s/%s",
		     (p->type & CUPS_PRINTER_CLASS) ? "classes" : "printers",
		     p->name);
    keyvalue[count  ][0] = "adminurl";
    keyvalue[count++][1] = adminurl_str;

    if (p->location)
    {
      keyvalue[count  ][0] = "note";
      keyvalue[count++][1] = p->location;
    }

    keyvalue[count  ][0] = "priority";
    keyvalue[count++][1] = for_lpd ? "100" : "0";

    keyvalue[count  ][0] = "product";
    keyvalue[count++][1] = p->pc && p->pc->product ? p->pc->product : "Unknown";

    keyvalue[count  ][0] = "pdl";
    keyvalue[count++][1] = p->pdl ? p->pdl : "application/postscript";

    /* iOS 6 does not accept this printer as AirPrint printer if there is
       no URF txt record or "URF=none", "DM3" is the minimum needed found
       by try and error */
    keyvalue[count  ][0] = "URF";
    keyvalue[count++][1] = "DM3";

    if (get_auth_info_required(p, air_str, sizeof(air_str)))
    {
      keyvalue[count  ][0] = "air";
      keyvalue[count++][1] = air_str;
    }

    keyvalue[count  ][0] = "UUID";
    keyvalue[count++][1] = p->uuid + 9;

  #ifdef HAVE_SSL
    keyvalue[count  ][0] = "TLS";
    keyvalue[count++][1] = "1.2";
  #endif /* HAVE_SSL */

    if (p->type & CUPS_PRINTER_FAX)
    {
      keyvalue[count  ][0] = "Fax";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_FAX) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_COLOR)
    {
      keyvalue[count  ][0] = "Color";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_COLOR) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_DUPLEX)
    {
      keyvalue[count  ][0] = "Duplex";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_DUPLEX) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_STAPLE)
    {
      keyvalue[count  ][0] = "Staple";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_STAPLE) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_COPIES)
    {
      keyvalue[count  ][0] = "Copies";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_COPIES) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_COLLATE)
    {
      keyvalue[count  ][0] = "Collate";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_COLLATE) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_PUNCH)
    {
      keyvalue[count  ][0] = "Punch";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_PUNCH) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_BIND)
    {
      keyvalue[count  ][0] = "Bind";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_BIND) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_SORT)
    {
      keyvalue[count  ][0] = "Sort";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_SORT) ? "T" : "F";
    }

    if (p->type & CUPS_PRINTER_MFP)
    {
      keyvalue[count  ][0] = "Scan";
      keyvalue[count++][1] = (p->type & CUPS_PRINTER_MFP) ? "T" : "F";
    }

    snprintf(type_str, sizeof(type_str), "0x%X", p->type | CUPS_PRINTER_REMOTE);
    snprintf(state_str, sizeof(state_str), "%d", p->state);

    keyvalue[count  ][0] = "printer-state";
    keyvalue[count++][1] = state_str;

    keyvalue[count  ][0] = "printer-type";
    keyvalue[count++][1] = type_str;
  }

 /*
  * Then pack them into a proper txt record...
  */

#  ifdef HAVE_DNSSD
  TXTRecordCreate(&txt, 0, NULL);

  for (i = 0; i < count; i ++)
  {
    size_t len = strlen(keyvalue[i][1]);

    if (len < 256)
      TXTRecordSetValue(&txt, keyvalue[i][0], (uint8_t)len, keyvalue[i][1]);
  }

#  else
  for (i = 0, txt = NULL; i < count; i ++)
    txt = avahi_string_list_add_printf(txt, "%s=%s", keyvalue[i][0],
                                       keyvalue[i][1]);
#  endif /* HAVE_DNSSD */

  return (txt);
}


/*
 * 'dnssdComparePrinters()' - Compare the registered names of two printers.
 */

static int				/* O - Result of comparison */
dnssdComparePrinters(cupsd_printer_t *a,/* I - First printer */
                     cupsd_printer_t *b)/* I - Second printer */
{
  if (!a || !a->reg_name)
    if (!b || !b->reg_name)
      return 0;
    else
      return -1;
  else
    if (!b || !b->reg_name)
      return 1;
    else
      return (_cups_strcasecmp(a->reg_name, b->reg_name));
}


/*
 * 'dnssdDeregisterInstance()' - Deregister a DNS-SD service instance.
 */

static void
dnssdDeregisterInstance(
    cupsd_srv_t     *srv)		/* I - Service */
{
  if (!srv || !*srv)
    return;

#  ifdef HAVE_DNSSD
  DNSServiceRefDeallocate(*srv);

#  else /* HAVE_AVAHI */
  avahi_threaded_poll_lock(DNSSDMaster);
  avahi_entry_group_free(*srv);
  avahi_threaded_poll_unlock(DNSSDMaster);
#  endif /* HAVE_DNSSD */

  *srv = NULL;
}


/*
 * 'dnssdDeregisterPrinter()' - Deregister all services for a printer.
 */

static void
dnssdDeregisterPrinter(
    cupsd_printer_t *p,			/* I - Printer */
    int             clear_name)		/* I - Clear the name? */

{
  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "dnssdDeregisterPrinter(p=%p(%s), clear_name=%d)", p, p->name,
                  clear_name);

  if (p->ipp_srv)
  {
    dnssdDeregisterInstance(&p->ipp_srv);

#  ifdef HAVE_DNSSD
#    ifdef HAVE_SSL
    dnssdDeregisterInstance(&p->ipps_srv);
#    endif /* HAVE_SSL */
    dnssdDeregisterInstance(&p->printer_srv);
#  endif /* HAVE_DNSSD */
  }

 /*
  * Remove the printer from the array of DNS-SD printers but keep the
  * registered name...
  */

  cupsArrayRemove(DNSSDPrinters, p);

 /*
  * Optionally clear the service name...
  */

  if (clear_name)
    cupsdClearString(&p->reg_name);
}


/*
 * 'dnssdErrorString()' - Return an error string for an error code.
 */

static const char *			/* O - Error message */
dnssdErrorString(int error)		/* I - Error number */
{
#  ifdef HAVE_DNSSD
  switch (error)
  {
    case kDNSServiceErr_NoError :
        return ("OK.");

    default :
    case kDNSServiceErr_Unknown :
        return ("Unknown error.");

    case kDNSServiceErr_NoSuchName :
        return ("Service not found.");

    case kDNSServiceErr_NoMemory :
        return ("Out of memory.");

    case kDNSServiceErr_BadParam :
        return ("Bad parameter.");

    case kDNSServiceErr_BadReference :
        return ("Bad service reference.");

    case kDNSServiceErr_BadState :
        return ("Bad state.");

    case kDNSServiceErr_BadFlags :
        return ("Bad flags.");

    case kDNSServiceErr_Unsupported :
        return ("Unsupported.");

    case kDNSServiceErr_NotInitialized :
        return ("Not initialized.");

    case kDNSServiceErr_AlreadyRegistered :
        return ("Already registered.");

    case kDNSServiceErr_NameConflict :
        return ("Name conflict.");

    case kDNSServiceErr_Invalid :
        return ("Invalid name.");

    case kDNSServiceErr_Firewall :
        return ("Firewall prevents registration.");

    case kDNSServiceErr_Incompatible :
        return ("Client library incompatible.");

    case kDNSServiceErr_BadInterfaceIndex :
        return ("Bad interface index.");

    case kDNSServiceErr_Refused :
        return ("Server prevents registration.");

    case kDNSServiceErr_NoSuchRecord :
        return ("Record not found.");

    case kDNSServiceErr_NoAuth :
        return ("Authentication required.");

    case kDNSServiceErr_NoSuchKey :
        return ("Encryption key not found.");

    case kDNSServiceErr_NATTraversal :
        return ("Unable to traverse NAT boundary.");

    case kDNSServiceErr_DoubleNAT :
        return ("Unable to traverse double-NAT boundary.");

    case kDNSServiceErr_BadTime :
        return ("Bad system time.");

    case kDNSServiceErr_BadSig :
        return ("Bad signature.");

    case kDNSServiceErr_BadKey :
        return ("Bad encryption key.");

    case kDNSServiceErr_Transient :
        return ("Transient error occurred - please try again.");

    case kDNSServiceErr_ServiceNotRunning :
        return ("Server not running.");

    case kDNSServiceErr_NATPortMappingUnsupported :
        return ("NAT doesn't support NAT-PMP or UPnP.");

    case kDNSServiceErr_NATPortMappingDisabled :
        return ("NAT supports NAT-PNP or UPnP but it is disabled.");

    case kDNSServiceErr_NoRouter :
        return ("No Internet/default router configured.");

    case kDNSServiceErr_PollingMode :
        return ("Service polling mode error.");

    case kDNSServiceErr_Timeout :
        return ("Service timeout.");
  }

#  else /* HAVE_AVAHI */
  return (avahi_strerror(error));
#  endif /* HAVE_DNSSD */
}


/*
 * 'dnssdRegisterCallback()' - Free a TXT record.
 */

static void
dnssdFreeTxtRecord(cupsd_txt_t *txt)	/* I - TXT record */
{
#  ifdef HAVE_DNSSD
  TXTRecordDeallocate(txt);

#  else /* HAVE_AVAHI */
  avahi_string_list_free(*txt);
  *txt = NULL;
#  endif /* HAVE_DNSSD */
}


/*
 * 'dnssdRegisterCallback()' - DNSServiceRegister callback.
 */

#  ifdef HAVE_DNSSD
static void
dnssdRegisterCallback(
    DNSServiceRef	sdRef,		/* I - DNS Service reference */
    DNSServiceFlags	flags,		/* I - Reserved for future use */
    DNSServiceErrorType	errorCode,	/* I - Error code */
    const char		*name,     	/* I - Service name */
    const char		*regtype,  	/* I - Service type */
    const char		*domain,   	/* I - Domain. ".local" for now */
    void		*context)	/* I - Printer */
{
  cupsd_printer_t *p = (cupsd_printer_t *)context;
					/* Current printer */


  (void)sdRef;
  (void)flags;
  (void)domain;

  cupsdLogMessage(CUPSD_LOG_DEBUG2, "dnssdRegisterCallback(%s, %s) for %s (%s)",
                  name, regtype, p ? p->name : "Web Interface",
		  p ? (p->reg_name ? p->reg_name : "(null)") : "NA");

  if (errorCode)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
		    "DNSServiceRegister failed with error %d", (int)errorCode);
    return;
  }
  else if (p && (!p->reg_name || _cups_strcasecmp(name, p->reg_name)))
  {
    cupsdLogMessage(CUPSD_LOG_INFO, "Using service name \"%s\" for \"%s\"",
                    name, p->name);

    cupsArrayRemove(DNSSDPrinters, p);
    cupsdSetString(&p->reg_name, name);
    cupsArrayAdd(DNSSDPrinters, p);

    LastEvent |= CUPSD_EVENT_PRINTER_MODIFIED;
  }
}

#  else /* HAVE_AVAHI */
static void
dnssdRegisterCallback(
    AvahiEntryGroup      *srv,		/* I - Service */
    AvahiEntryGroupState state,		/* I - Registration state */
    void                 *context)	/* I - Printer */
{
  cupsd_printer_t *p = (cupsd_printer_t *)context;
					/* Current printer */

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "dnssdRegisterCallback(srv=%p, state=%d, context=%p) "
                  "for %s (%s)", srv, state, context,
                  p ? p->name : "Web Interface",
		  p ? (p->reg_name ? p->reg_name : "(null)") : "NA");

  /* TODO: Handle collisions with avahi_alternate_service_name(p->reg_name)? */
}
#  endif /* HAVE_DNSSD */


/*
 * 'dnssdRegisterInstance()' - Register an instance of a printer service.
 */

static int				/* O - 1 on success, 0 on failure */
dnssdRegisterInstance(
    cupsd_srv_t     *srv,		/* O - Service */
    cupsd_printer_t *p,			/* I - Printer */
    char            *name,		/* I - DNS-SD service name */
    const char      *type,		/* I - DNS-SD service type */
    const char      *subtypes,		/* I - Subtypes to register or NULL */
    int             port,		/* I - Port number or 0 */
    cupsd_txt_t     *txt,		/* I - TXT record */
    int             commit)		/* I - Commit registration? */
{
  char	temp[256],			/* Temporary string */
	*ptr;				/* Pointer into string */
  int	error;				/* Any error */


  cupsdLogMessage(CUPSD_LOG_DEBUG,
		  "Registering \"%s\" with DNS-SD type \"%s\".", name, type);

  if (p && !srv)
  {
   /*
    * Assign the correct pointer for "srv"...
    */

#  ifdef HAVE_DNSSD
    if (!strcmp(type, "_printer._tcp"))
      srv = &p->printer_srv;		/* Target LPD service */
#    ifdef HAVE_SSL
    else if (!strcmp(type, "_ipps._tcp"))
      srv = &p->ipps_srv;		/* Target IPPS service */
#    endif /* HAVE_SSL */
    else
      srv = &p->ipp_srv;		/* Target IPP service */

#  else /* HAVE_AVAHI */
    srv = &p->ipp_srv;			/* Target service group */
#  endif /* HAVE_DNSSD */
  }

#  ifdef HAVE_DNSSD
  (void)commit;

#  else /* HAVE_AVAHI */
  avahi_threaded_poll_lock(DNSSDMaster);

  if (!*srv)
    *srv = avahi_entry_group_new(DNSSDClient, dnssdRegisterCallback, NULL);
  if (!*srv)
  {
    avahi_threaded_poll_unlock(DNSSDMaster);

    cupsdLogMessage(CUPSD_LOG_WARN, "DNS-SD registration of \"%s\" failed: %s",
                    name, dnssdErrorString(avahi_client_errno(DNSSDClient)));
    return (0);
  }
#  endif /* HAVE_DNSSD */

 /*
  * Make sure the name is <= 63 octets, and when we truncate be sure to
  * properly truncate any UTF-8 characters...
  */

  ptr = name + strlen(name);
  while ((ptr - name) > 63)
  {
    do
    {
      ptr --;
    }
    while (ptr > name && (*ptr & 0xc0) == 0x80);

    if (ptr > name)
      *ptr = '\0';
  }

 /*
  * Register the service...
  */

#  ifdef HAVE_DNSSD
  if (subtypes)
    snprintf(temp, sizeof(temp), "%s,%s", type, subtypes);
  else
    strlcpy(temp, type, sizeof(temp));

  *srv  = DNSSDMaster;
  error = DNSServiceRegister(srv, kDNSServiceFlagsShareConnection,
			     0, name, temp, NULL, NULL, htons(port),
			     txt ? TXTRecordGetLength(txt) : 0,
			     txt ? TXTRecordGetBytesPtr(txt) : NULL,
			     dnssdRegisterCallback, p);

#  else /* HAVE_AVAHI */
  if (txt)
  {
    AvahiStringList *temptxt;
    for (temptxt = *txt; temptxt; temptxt = temptxt->next)
      cupsdLogMessage(CUPSD_LOG_DEBUG, "DNS_SD \"%s\" %s", name, temptxt->text);
  }

  error = avahi_entry_group_add_service_strlst(*srv, AVAHI_IF_UNSPEC,
                                               AVAHI_PROTO_UNSPEC, 0, name,
                                               type, NULL, NULL, port,
                                               txt ? *txt : NULL);
  if (error)
    cupsdLogMessage(CUPSD_LOG_DEBUG, "DNS-SD service add for \"%s\" failed.",
                    name);

  if (!error && subtypes)
  {
   /*
    * Register all of the subtypes...
    */

    char	*start,			/* Start of subtype */
		subtype[256];		/* Subtype string */

    strlcpy(temp, subtypes, sizeof(temp));

    for (start = temp; *start; start = ptr)
    {
     /*
      * Skip leading whitespace...
      */

      while (*start && isspace(*start & 255))
        start ++;

     /*
      * Grab everything up to the next comma or the end of the string...
      */

      for (ptr = start; *ptr && *ptr != ','; ptr ++);

      if (*ptr)
        *ptr++ = '\0';

      if (!*start)
        break;

     /*
      * Register the subtype...
      */

      snprintf(subtype, sizeof(subtype), "%s._sub.%s", start, type);

      error = avahi_entry_group_add_service_subtype(*srv, AVAHI_IF_UNSPEC,
                                                    AVAHI_PROTO_UNSPEC, 0,
                                                    name, type, NULL, subtype);
      if (error)
      {
        cupsdLogMessage(CUPSD_LOG_DEBUG,
                        "DNS-SD subtype %s registration for \"%s\" failed." ,
                        subtype, name);
        break;
      }
    }
  }

  if (!error && commit)
  {
    if ((error = avahi_entry_group_commit(*srv)) != 0)
      cupsdLogMessage(CUPSD_LOG_DEBUG, "DNS-SD commit of \"%s\" failed.",
                      name);
  }

  avahi_threaded_poll_unlock(DNSSDMaster);
#  endif /* HAVE_DNSSD */

  if (error)
  {
    cupsdLogMessage(CUPSD_LOG_WARN, "DNS-SD registration of \"%s\" failed: %s",
                    name, dnssdErrorString(error));
    cupsdLogMessage(CUPSD_LOG_DEBUG, "DNS-SD type: %s", type);
    if (subtypes)
      cupsdLogMessage(CUPSD_LOG_DEBUG, "DNS-SD sub-types: %s", subtypes);
  }

  return (!error);
}


/*
 * 'dnssdRegisterPrinter()' - Start sending broadcast information for a printer
 *		              or update the broadcast contents.
 */

static void
dnssdRegisterPrinter(cupsd_printer_t *p)/* I - Printer */
{
  char		name[256];		/* Service name */
  int		printer_port;		/* LPD port number */
  int		status;			/* Registration status */
  cupsd_txt_t	ipp_txt,		/* IPP(S) TXT record */
 		printer_txt;		/* LPD TXT record */

  cupsdLogMessage(CUPSD_LOG_DEBUG2, "dnssdRegisterPrinter(%s) %s", p->name,
                  !p->ipp_srv ? "new" : "update");

 /*
  * Remove the current registrations if we have them and then return if
  * per-printer sharing was just disabled...
  */

  dnssdDeregisterPrinter(p, 0);

  if (!p->shared)
    return;

 /*
  * Set the registered name as needed; the registered name takes the form of
  * "<printer-info> @ <computer name>"...
  */

  if (!p->reg_name)
  {
    if (p->info && strlen(p->info) > 0)
    {
      if (DNSSDComputerName)
	snprintf(name, sizeof(name), "%s @ %s", p->info, DNSSDComputerName);
      else
	strlcpy(name, p->info, sizeof(name));
    }
    else if (DNSSDComputerName)
      snprintf(name, sizeof(name), "%s @ %s", p->name, DNSSDComputerName);
    else
      strlcpy(name, p->name, sizeof(name));
  }
  else
    strlcpy(name, p->reg_name, sizeof(name));

 /*
  * Register IPP and LPD...
  *
  * We always must register the "_printer" service type in order to reserve
  * our name, but use port number 0 if we haven't actually configured cups-lpd
  * to share via LPD...
  */

  ipp_txt     = dnssdBuildTxtRecord(p, 0);
  printer_txt = dnssdBuildTxtRecord(p, 1);

  if (BrowseLocalProtocols & BROWSE_LPD)
    printer_port = 515;
  else
    printer_port = 0;

  status = dnssdRegisterInstance(NULL, p, name, "_printer._tcp", NULL,
                                 printer_port, &printer_txt, 0);

#  ifdef HAVE_SSL
  if (status)
    dnssdRegisterInstance(NULL, p, name, "_ipps._tcp", DNSSDSubTypes,
			  DNSSDPort, &ipp_txt, 0);
#  endif /* HAVE_SSL */

  if (status)
  {
   /*
    * Use the "_fax-ipp" service type for fax queues, otherwise use "_ipp"...
    */

    if (p->type & CUPS_PRINTER_FAX)
      status = dnssdRegisterInstance(NULL, p, name, "_fax-ipp._tcp",
                                     DNSSDSubTypes, DNSSDPort, &ipp_txt, 1);
    else
      status = dnssdRegisterInstance(NULL, p, name, "_ipp._tcp", DNSSDSubTypes,
                                     DNSSDPort, &ipp_txt, 1);
  }

  dnssdFreeTxtRecord(&ipp_txt);
  dnssdFreeTxtRecord(&printer_txt);

  if (status)
  {
   /*
    * Save the registered name and add the printer to the array of DNS-SD
    * printers...
    */

    cupsdSetString(&p->reg_name, name);
    cupsArrayAdd(DNSSDPrinters, p);
  }
  else
  {
   /*
    * Registration failed for this printer...
    */

    dnssdDeregisterInstance(&p->ipp_srv);

#  ifdef HAVE_DNSSD
#    ifdef HAVE_SSL
    dnssdDeregisterInstance(&p->ipps_srv);
#    endif /* HAVE_SSL */
    dnssdDeregisterInstance(&p->printer_srv);
#  endif /* HAVE_DNSSD */
  }
}


/*
 * 'dnssdStop()' - Stop all DNS-SD registrations.
 */

static void
dnssdStop(void)
{
  cupsd_printer_t	*p;		/* Current printer */


 /*
  * De-register the individual printers
  */

  for (p = (cupsd_printer_t *)cupsArrayFirst(Printers);
       p;
       p = (cupsd_printer_t *)cupsArrayNext(Printers))
    dnssdDeregisterPrinter(p, 1);

 /*
  * Shutdown the rest of the service refs...
  */

  dnssdDeregisterInstance(&WebIFSrv);

#  ifdef HAVE_DNSSD
  cupsdRemoveSelect(DNSServiceRefSockFD(DNSSDMaster));

  DNSServiceRefDeallocate(DNSSDMaster);
  DNSSDMaster = NULL;

#  else /* HAVE_AVAHI */
  avahi_threaded_poll_stop(DNSSDMaster);
  avahi_client_free(DNSSDClient);
  DNSSDClient = NULL;

  avahi_threaded_poll_free(DNSSDMaster);
  DNSSDMaster = NULL;
#  endif /* HAVE_DNSSD */

  cupsArrayDelete(DNSSDPrinters);
  DNSSDPrinters = NULL;

  DNSSDPort = 0;
}


#  ifdef HAVE_DNSSD
/*
 * 'dnssdUpdate()' - Handle DNS-SD queries.
 */

static void
dnssdUpdate(void)
{
  DNSServiceErrorType	sdErr;		/* Service discovery error */


  if ((sdErr = DNSServiceProcessResult(DNSSDMaster)) != kDNSServiceErr_NoError)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "DNS Service Discovery registration error %d!",
	            sdErr);
    dnssdStop();
  }
}
#  endif /* HAVE_DNSSD */
#endif /* HAVE_DNSSD || HAVE_AVAHI */


/*
 * 'get_auth_info_required()' - Get the auth-info-required value to advertise.
 */

static char *				/* O - String or NULL if none */
get_auth_info_required(
    cupsd_printer_t *p,			/* I - Printer */
    char            *buffer,		/* I - Value buffer */
    size_t          bufsize)		/* I - Size of value buffer */
{
  cupsd_location_t *auth;		/* Pointer to authentication element */
  char		resource[1024];		/* Printer/class resource path */


 /*
  * If auth-info-required is set for this printer, return that...
  */

  if (p->num_auth_info_required > 0 && strcmp(p->auth_info_required[0], "none"))
  {
    int		i;			/* Looping var */
    char	*bufptr;		/* Pointer into buffer */

    for (i = 0, bufptr = buffer; i < p->num_auth_info_required; i ++)
    {
      if (bufptr >= (buffer + bufsize - 2))
	break;

      if (i)
	*bufptr++ = ',';

      strlcpy(bufptr, p->auth_info_required[i], bufsize - (bufptr - buffer));
      bufptr += strlen(bufptr);
    }

    return (buffer);
  }

 /*
  * Figure out the authentication data requirements to advertise...
  */

  if (p->type & CUPS_PRINTER_CLASS)
    snprintf(resource, sizeof(resource), "/classes/%s", p->name);
  else
    snprintf(resource, sizeof(resource), "/printers/%s", p->name);

  if ((auth = cupsdFindBest(resource, HTTP_POST)) == NULL ||
      auth->type == CUPSD_AUTH_NONE)
    auth = cupsdFindPolicyOp(p->op_policy_ptr, IPP_PRINT_JOB);

  if (auth)
  {
    int	auth_type;			/* Authentication type */

    if ((auth_type = auth->type) == CUPSD_AUTH_DEFAULT)
      auth_type = cupsdDefaultAuthType();

    switch (auth_type)
    {
      case CUPSD_AUTH_NONE :
          return (NULL);

      case CUPSD_AUTH_NEGOTIATE :
	  strlcpy(buffer, "negotiate", bufsize);
	  break;

      default :
	  strlcpy(buffer, "username,password", bufsize);
	  break;
    }

    return (buffer);
  }

  return ("none");
}


#ifdef __APPLE__
/*
 * 'get_hostconfig()' - Get an /etc/hostconfig service setting.
 */

static int				/* O - 1 for YES or AUTOMATIC, 0 for NO */
get_hostconfig(const char *name)	/* I - Name of service */
{
  cups_file_t	*fp;			/* Hostconfig file */
  char		line[1024],		/* Line from file */
		*ptr;			/* Pointer to value */
  int		state = 1;		/* State of service */


 /*
  * Try opening the /etc/hostconfig file; if we can't open it, assume that
  * the service is enabled/auto.
  */

  if ((fp = cupsFileOpen("/etc/hostconfig", "r")) != NULL)
  {
   /*
    * Read lines from the file until we find the service...
    */

    while (cupsFileGets(fp, line, sizeof(line)))
    {
      if (line[0] == '#' || (ptr = strchr(line, '=')) == NULL)
        continue;

      *ptr++ = '\0';

      if (!_cups_strcasecmp(line, name))
      {
       /*
        * Found the service, see if it is set to "-NO-"...
	*/

	if (!_cups_strncasecmp(ptr, "-NO-", 4))
	  state = 0;
        break;
      }
    }

    cupsFileClose(fp);
  }

  return (state);
}
#endif /* __APPLE__ */


/*
 * 'is_local_queue()' - Determine whether the URI points at a local queue.
 */

static int				/* O - 1 = local, 0 = remote, -1 = bad URI */
is_local_queue(const char *uri,		/* I - Printer URI */
               char       *host,	/* O - Host string */
	       int        hostlen,	/* I - Length of host buffer */
               char       *resource,	/* O - Resource string */
	       int        resourcelen)	/* I - Length of resource buffer */
{
  char		scheme[32],		/* Scheme portion of URI */
		username[HTTP_MAX_URI];	/* Username portion of URI */
  int		port;			/* Port portion of URI */
  cupsd_netif_t	*iface;			/* Network interface */


 /*
  * Pull the URI apart to see if this is a local or remote printer...
  */

  if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme),
                      username, sizeof(username), host, hostlen, &port,
		      resource, resourcelen) < HTTP_URI_OK)
    return (-1);

  DEBUG_printf(("host=\"%s\", ServerName=\"%s\"\n", host, ServerName));

 /*
  * Check for local server addresses...
  */

  if (!_cups_strcasecmp(host, ServerName) && port == LocalPort)
    return (1);

  cupsdNetIFUpdate();

  for (iface = (cupsd_netif_t *)cupsArrayFirst(NetIFList);
       iface;
       iface = (cupsd_netif_t *)cupsArrayNext(NetIFList))
    if (!_cups_strcasecmp(host, iface->hostname) && port == iface->port)
      return (1);

 /*
  * If we get here, the printer is remote...
  */

  return (0);
}


/*
 * 'process_browse_data()' - Process new browse data.
 */

static void
process_browse_data(
    const char    *uri,			/* I - URI of printer/class */
    const char    *host,		/* I - Hostname */
    const char    *resource,		/* I - Resource path */
    cups_ptype_t  type,			/* I - Printer type */
    ipp_pstate_t  state,		/* I - Printer state */
    const char    *location,		/* I - Printer location */
    const char    *info,		/* I - Printer information */
    const char    *make_model,		/* I - Printer make and model */
    int		  num_attrs,		/* I - Number of attributes */
    cups_option_t *attrs)		/* I - Attributes */
{
  int		i;			/* Looping var */
  int		update;			/* Update printer attributes? */
  char		finaluri[HTTP_MAX_URI],	/* Final URI for printer */
		name[IPP_MAX_NAME],	/* Name of printer */
		newname[IPP_MAX_NAME],	/* New name of printer */
		*hptr,			/* Pointer into hostname */
		*sptr;			/* Pointer into ServerName */
  const char	*shortname;		/* Short queue name (queue) */
  char		local_make_model[IPP_MAX_NAME];
					/* Local make and model */
  cupsd_printer_t *p;			/* Printer information */
  const char	*ipp_options,		/* ipp-options value */
		*lease_duration,	/* lease-duration value */
		*uuid;			/* uuid value */
  int		is_class;		/* Is this queue a class? */


  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "process_browse_data(uri=\"%s\", host=\"%s\", "
		  "resource=\"%s\", type=%x, state=%d, location=\"%s\", "
		  "info=\"%s\", make_model=\"%s\", num_attrs=%d, attrs=%p)",
		  uri, host, resource, type, state,
		  location ? location : "(nil)", info ? info : "(nil)",
		  make_model ? make_model : "(nil)", num_attrs, attrs);

 /*
  * Determine if the URI contains any illegal characters in it...
  */

  if (strncmp(uri, "ipp://", 6) || !host[0] ||
      (strncmp(resource, "/printers/", 10) &&
       strncmp(resource, "/classes/", 9)))
  {
    cupsdLogMessage(CUPSD_LOG_ERROR, "Bad printer URI in browse data: %s", uri);
    return;
  }

  if (strchr(resource, '?') ||
      (!strncmp(resource, "/printers/", 10) && strchr(resource + 10, '/')) ||
      (!strncmp(resource, "/classes/", 9) && strchr(resource + 9, '/')))
  {
    cupsdLogMessage(CUPSD_LOG_ERROR, "Bad resource in browse data: %s",
                    resource);
    return;
  }

 /*
  * OK, this isn't a local printer; add any remote options...
  */

  ipp_options = cupsGetOption("ipp-options", num_attrs, attrs);

  if (BrowseRemoteOptions)
  {
    if (BrowseRemoteOptions[0] == '?')
    {
     /*
      * Override server-supplied options...
      */

      snprintf(finaluri, sizeof(finaluri), "%s%s", uri, BrowseRemoteOptions);
    }
    else if (ipp_options)
    {
     /*
      * Combine the server and local options...
      */

      snprintf(finaluri, sizeof(finaluri), "%s?%s+%s", uri, ipp_options,
               BrowseRemoteOptions);
    }
    else
    {
     /*
      * Just use the local options...
      */

      snprintf(finaluri, sizeof(finaluri), "%s?%s", uri, BrowseRemoteOptions);
    }

    uri = finaluri;
  }
  else if (ipp_options)
  {
   /*
    * Just use the server-supplied options...
    */

    snprintf(finaluri, sizeof(finaluri), "%s?%s", uri, ipp_options);
    uri = finaluri;
  }

 /*
  * See if we already have it listed in the Printers list, and add it if not...
  */

  type     |= CUPS_PRINTER_REMOTE | CUPS_PRINTER_DISCOVERED;
  type     &= ~CUPS_PRINTER_IMPLICIT;
  update   = 0;
  hptr     = strchr(host, '.');
  sptr     = strchr(ServerName, '.');
  is_class = type & CUPS_PRINTER_CLASS;
  uuid     = cupsGetOption("uuid", num_attrs, attrs);

  if (!ServerNameIsIP && sptr != NULL && hptr != NULL)
  {
   /*
    * Strip the common domain name components...
    */

    while (hptr != NULL)
    {
      if (!_cups_strcasecmp(hptr, sptr))
      {
        *hptr = '\0';
	break;
      }
      else
        hptr = strchr(hptr + 1, '.');
    }
  }

  if (is_class)
  {
   /*
    * Remote destination is a class...
    */

    if (!strncmp(resource, "/classes/", 9))
      snprintf(name, sizeof(name), "%s@%s", resource + 9, host);
    else
      return;

    shortname = resource + 9;
  }
  else
  {
   /*
    * Remote destination is a printer...
    */

    if (!strncmp(resource, "/printers/", 10))
      snprintf(name, sizeof(name), "%s@%s", resource + 10, host);
    else
      return;

    shortname = resource + 10;
  }

  if (hptr && !*hptr)
    *hptr = '.';			/* Resource FQDN */

  if ((p = cupsdFindDest(name)) == NULL && BrowseShortNames)
  {
   /*
    * Long name doesn't exist, try short name...
    */

    cupsdLogMessage(CUPSD_LOG_DEBUG, "process_browse_data: %s not found...",
                    name);

    if ((p = cupsdFindDest(shortname)) == NULL)
    {
     /*
      * Short name doesn't exist, use it for this shared queue.
      */

      cupsdLogMessage(CUPSD_LOG_DEBUG2, "process_browse_data: %s not found...",
		      shortname);
      strlcpy(name, shortname, sizeof(name));
    }
    else
    {
     /*
      * Short name exists...
      */

      cupsdLogMessage(CUPSD_LOG_DEBUG2,
                      "process_browse_data: %s found, type=%x, hostname=%s...",
		      shortname, p->type, p->hostname ? p->hostname : "(nil)");

      if (p->type & CUPS_PRINTER_IMPLICIT)
        p = NULL;			/* Don't replace implicit classes */
      else if (p->hostname && _cups_strcasecmp(p->hostname, host))
      {
       /*
	* Short name exists but is for a different host.  If this is a remote
	* queue, rename it and use the long name...
	*/

	if (p->type & CUPS_PRINTER_REMOTE)
	{
	  cupsdLogMessage(CUPSD_LOG_DEBUG,
			  "Renamed remote %s \"%s\" to \"%s@%s\"...",
			  is_class ? "class" : "printer", p->name, p->name,
			  p->hostname);
	  cupsdAddEvent(CUPSD_EVENT_PRINTER_DELETED, p, NULL,
			"%s \'%s\' deleted by directory services.",
			is_class ? "Class" : "Printer", p->name);

	  snprintf(newname, sizeof(newname), "%s@%s", p->name, p->hostname);
	  cupsdRenamePrinter(p, newname);

	  cupsdAddEvent(CUPSD_EVENT_PRINTER_ADDED, p, NULL,
			"%s \'%s\' added by directory services.",
			is_class ? "Class" : "Printer", p->name);
	}

       /*
        * Force creation with long name...
	*/

	p = NULL;
      }
    }
  }
  else if (p)
    cupsdLogMessage(CUPSD_LOG_DEBUG2,
		    "process_browse_data: %s found, type=%x, hostname=%s...",
		    name, p->type, p->hostname ? p->hostname : "(nil)");

  if (!p)
  {
   /*
    * Queue doesn't exist; add it...
    */

    if (is_class)
      p = cupsdAddClass(name);
    else
      p = cupsdAddPrinter(name);

    if (!p)
      return;

    cupsdClearString(&(p->hostname));

    cupsdLogMessage(CUPSD_LOG_DEBUG, "Added remote %s \"%s\"...",
                    is_class ? "class" : "printer", name);

    cupsdAddEvent(CUPSD_EVENT_PRINTER_ADDED, p, NULL,
		  "%s \'%s\' added by directory services.",
		  is_class ? "Class" : "Printer", name);

   /*
    * Force the URI to point to the real server...
    */

    p->type      = type & ~CUPS_PRINTER_REJECTING;
    p->accepting = 1;

    cupsdMarkDirty(CUPSD_DIRTY_PRINTCAP);
  }

  if (!p->hostname)
  {
   /*
    * Hostname not set, so this must be a cached remote printer
    * that was created for a pending print job...
    */

    cupsdSetString(&p->hostname, host);
    cupsdSetString(&p->uri, uri);
    cupsdSetString(&p->device_uri, uri);
    update = 1;

    cupsdMarkDirty(CUPSD_DIRTY_REMOTE);
  }

 /*
  * Update the state...
  */

  p->state       = state;
  p->browse_time = time(NULL);

  if ((lease_duration = cupsGetOption("lease-duration", num_attrs,
                                      attrs)) != NULL)
  {
   /*
    * Grab the lease-duration for the browse data; anything less then 1
    * second or more than 1 week gets the default BrowseTimeout...
    */

    i = atoi(lease_duration);
    if (i < 1 || i > 604800)
      i = BrowseTimeout;

    p->browse_expire = p->browse_time + i;
  }
  else
    p->browse_expire = p->browse_time + BrowseTimeout;

  if (type & CUPS_PRINTER_REJECTING)
  {
    type &= ~CUPS_PRINTER_REJECTING;

    if (p->accepting)
    {
      update       = 1;
      p->accepting = 0;
    }
  }
  else if (!p->accepting)
  {
    update       = 1;
    p->accepting = 1;
  }

  if (p->type != type)
  {
    p->type = type;
    update  = 1;
  }

  if (uuid && strcmp(p->uuid, uuid))
  {
    cupsdSetString(&p->uuid, uuid);
    update = 1;
  }

  if (location && (!p->location || strcmp(p->location, location)))
  {
    cupsdSetString(&p->location, location);
    update = 1;
  }

  if (info && (!p->info || strcmp(p->info, info)))
  {
    cupsdSetString(&p->info, info);
    update = 1;

    cupsdMarkDirty(CUPSD_DIRTY_PRINTCAP | CUPSD_DIRTY_REMOTE);
  }

  if (!make_model || !make_model[0])
  {
    if (is_class)
      snprintf(local_make_model, sizeof(local_make_model),
               "Remote Class on %s", host);
    else
      snprintf(local_make_model, sizeof(local_make_model),
               "Remote Printer on %s", host);
  }
  else
    snprintf(local_make_model, sizeof(local_make_model),
             "%s on %s", make_model, host);

  if (!p->make_model || strcmp(p->make_model, local_make_model))
  {
    cupsdSetString(&p->make_model, local_make_model);
    update = 1;
  }

  if (p->num_options)
  {
    if (!update && !(type & CUPS_PRINTER_DELETE))
    {
     /*
      * See if we need to update the attributes...
      */

      if (p->num_options != num_attrs)
	update = 1;
      else
      {
	for (i = 0; i < num_attrs; i ++)
          if (strcmp(attrs[i].name, p->options[i].name) ||
	      (!attrs[i].value != !p->options[i].value) ||
	      (attrs[i].value && strcmp(attrs[i].value, p->options[i].value)))
          {
	    update = 1;
	    break;
          }
      }
    }

   /*
    * Free the old options...
    */

    cupsFreeOptions(p->num_options, p->options);
  }

  p->num_options = num_attrs;
  p->options     = attrs;

  if (type & CUPS_PRINTER_DELETE)
  {
    cupsdAddEvent(CUPSD_EVENT_PRINTER_DELETED, p, NULL,
                  "%s \'%s\' deleted by directory services.",
		  is_class ? "Class" : "Printer", p->name);

    cupsdExpireSubscriptions(p, NULL);

    cupsdDeletePrinter(p, 1);
    cupsdUpdateImplicitClasses();
    cupsdMarkDirty(CUPSD_DIRTY_PRINTCAP | CUPSD_DIRTY_REMOTE);
  }
  else if (update)
  {
    cupsdSetPrinterAttrs(p);
    cupsdUpdateImplicitClasses();
  }

 /*
  * See if we have a default printer...  If not, make the first network
  * default printer the default.
  */

  if (DefaultPrinter == NULL && Printers != NULL && UseNetworkDefault)
  {
   /*
    * Find the first network default printer and use it...
    */

    for (p = (cupsd_printer_t *)cupsArrayFirst(Printers);
         p;
	 p = (cupsd_printer_t *)cupsArrayNext(Printers))
      if (p->type & CUPS_PRINTER_DEFAULT)
      {
        DefaultPrinter = p;
        cupsdMarkDirty(CUPSD_DIRTY_PRINTCAP | CUPSD_DIRTY_REMOTE);
	break;
      }
  }

 /*
  * Do auto-classing if needed...
  */

  process_implicit_classes();
}


/*
 * 'process_implicit_classes()' - Create/update implicit classes as needed.
 */

static void
process_implicit_classes(void)
{
  int		i;			/* Looping var */
  int		update;			/* Update printer attributes? */
  char		name[IPP_MAX_NAME],	/* Name of printer */
		*hptr;			/* Pointer into hostname */
  cupsd_printer_t *p,			/* Printer information */
		*pclass,		/* Printer class */
		*first;			/* First printer in class */
  int		offset,			/* Offset of name */
		len;			/* Length of name */


  if (!ImplicitClasses || !Printers)
    return;

 /*
  * Loop through all available printers and create classes as needed...
  */

  for (p = (cupsd_printer_t *)cupsArrayFirst(Printers), len = 0, offset = 0,
           update = 0, pclass = NULL, first = NULL;
       p != NULL;
       p = (cupsd_printer_t *)cupsArrayNext(Printers))
  {
   /*
    * Skip implicit classes...
    */

    if (p->type & CUPS_PRINTER_IMPLICIT)
    {
      len = 0;
      continue;
    }

   /*
    * If len == 0, get the length of this printer name up to the "@"
    * sign (if any).
    */

    cupsArraySave(Printers);

    if (len > 0 &&
	!_cups_strncasecmp(p->name, name + offset, len) &&
	(p->name[len] == '\0' || p->name[len] == '@'))
    {
     /*
      * We have more than one printer with the same name; see if
      * we have a class, and if this printer is a member...
      */

      if (pclass && _cups_strcasecmp(pclass->name, name))
      {
	if (update)
	  cupsdSetPrinterAttrs(pclass);

	update = 0;
	pclass = NULL;
      }

      if (!pclass && (pclass = cupsdFindDest(name)) == NULL)
      {
       /*
	* Need to add the class...
	*/

	pclass = cupsdAddPrinter(name);
	cupsArrayAdd(ImplicitPrinters, pclass);

	pclass->type      |= CUPS_PRINTER_IMPLICIT;
	pclass->accepting = 1;
	pclass->state     = IPP_PRINTER_IDLE;

        cupsdSetString(&pclass->location, p->location);
        cupsdSetString(&pclass->info, p->info);

        cupsdSetString(&pclass->job_sheets[0], p->job_sheets[0]);
        cupsdSetString(&pclass->job_sheets[1], p->job_sheets[1]);

        update = 1;

	cupsdMarkDirty(CUPSD_DIRTY_PRINTCAP | CUPSD_DIRTY_REMOTE);

        cupsdLogMessage(CUPSD_LOG_DEBUG, "Added implicit class \"%s\"...",
	                name);
	cupsdAddEvent(CUPSD_EVENT_PRINTER_ADDED, p, NULL,
                      "Implicit class \'%s\' added by directory services.",
		      name);
      }

      if (first != NULL)
      {
        for (i = 0; i < pclass->num_printers; i ++)
	  if (pclass->printers[i] == first)
	    break;

        if (i >= pclass->num_printers)
	{
	  first->in_implicit_class = 1;
	  cupsdAddPrinterToClass(pclass, first);
        }

	first = NULL;
      }

      for (i = 0; i < pclass->num_printers; i ++)
	if (pclass->printers[i] == p)
	  break;

      if (i >= pclass->num_printers)
      {
	p->in_implicit_class = 1;
	cupsdAddPrinterToClass(pclass, p);
	update = 1;
      }
    }
    else
    {
     /*
      * First time around; just get name length and mark it as first
      * in the list...
      */

      if ((hptr = strchr(p->name, '@')) != NULL)
	len = hptr - p->name;
      else
	len = strlen(p->name);

      if (len >= sizeof(name))
      {
       /*
	* If the printer name length somehow is greater than we normally allow,
	* skip this printer...
	*/

	len = 0;
	cupsArrayRestore(Printers);
	continue;
      }

      strncpy(name, p->name, len);
      name[len] = '\0';
      offset    = 0;

      if ((first = (hptr ? cupsdFindDest(name) : p)) != NULL &&
	  !(first->type & CUPS_PRINTER_IMPLICIT))
      {
       /*
	* Can't use same name as a local printer; add "Any" to the
	* front of the name, unless we have explicitly disabled
	* the "ImplicitAnyClasses"...
	*/

        if (ImplicitAnyClasses && len < (sizeof(name) - 4))
	{
	 /*
	  * Add "Any" to the class name...
	  */

          strcpy(name, "Any");
          strncpy(name + 3, p->name, len);
	  name[len + 3] = '\0';
	  offset        = 3;
	}
	else
	{
	 /*
	  * Don't create an implicit class if we have a local printer
	  * with the same name...
	  */

	  len = 0;
          cupsArrayRestore(Printers);
	  continue;
	}
      }

      first = p;
    }

    cupsArrayRestore(Printers);
  }

 /*
  * Update the last printer class as needed...
  */

  if (pclass && update)
    cupsdSetPrinterAttrs(pclass);
}


/*
 * 'send_cups_browse()' - Send new browsing information using the CUPS
 *                        protocol.
 */

static void
send_cups_browse(cupsd_printer_t *p)	/* I - Printer to send */
{
  int			i;		/* Looping var */
  cups_ptype_t		type;		/* Printer type */
  cupsd_dirsvc_addr_t	*b;		/* Browse address */
  int			bytes;		/* Length of packet */
  char			packet[1453],	/* Browse data packet */
			uri[1024],	/* Printer URI */
			location[1024],	/* printer-location */
			info[1024],	/* printer-info */
			make_model[1024],
					/* printer-make-and-model */
			air[1024];	/* auth-info-required */
  cupsd_netif_t		*iface;		/* Network interface */


 /*
  * Figure out the printer type value...
  */

  type = p->type | CUPS_PRINTER_REMOTE;

  if (!p->accepting)
    type |= CUPS_PRINTER_REJECTING;

  if (p == DefaultPrinter)
    type |= CUPS_PRINTER_DEFAULT;

 /*
  * Remove quotes from printer-info, printer-location, and
  * printer-make-and-model attributes...
  */

  dequote(location, p->location, sizeof(location));
  dequote(info, p->info, sizeof(info));

  if (p->make_model)
    dequote(make_model, p->make_model, sizeof(make_model));
  else if (p->type & CUPS_PRINTER_CLASS)
  {
    if (p->num_printers > 0 && p->printers[0]->make_model)
      strlcpy(make_model, p->printers[0]->make_model, sizeof(make_model));
    else
      strlcpy(make_model, "Local Printer Class", sizeof(make_model));
  }
  else if (p->raw)
    strlcpy(make_model, "Local Raw Printer", sizeof(make_model));
  else
    strlcpy(make_model, "Local System V Printer", sizeof(make_model));

  if (get_auth_info_required(p, packet, sizeof(packet)))
    snprintf(air, sizeof(air), " auth-info-required=%s", packet);
  else
    air[0] = '\0';

 /*
  * Send a packet to each browse address...
  */

  for (i = NumBrowsers, b = Browsers; i > 0; i --, b ++)
    if (b->iface[0])
    {
     /*
      * Send the browse packet to one or more interfaces...
      */

      if (!strcmp(b->iface, "*"))
      {
       /*
        * Send to all local interfaces...
	*/

        cupsdNetIFUpdate();

	for (iface = (cupsd_netif_t *)cupsArrayFirst(NetIFList);
	     iface;
	     iface = (cupsd_netif_t *)cupsArrayNext(NetIFList))
	{
	 /*
	  * Only send to local, IPv4 interfaces...
	  */

	  if (!iface->is_local || !iface->port ||
	      iface->address.addr.sa_family != AF_INET)
	    continue;

	  httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
	                   iface->hostname, iface->port,
			   (p->type & CUPS_PRINTER_CLASS) ? "/classes/%s" :
			                                    "/printers/%s",
			   p->name);
	  snprintf(packet, sizeof(packet),
	           "%x %x %s \"%s\" \"%s\" \"%s\" %s%s uuid=%s\n",
        	   type, p->state, uri, location, info, make_model,
		   p->browse_attrs ? p->browse_attrs : "", air, p->uuid);

	  bytes = strlen(packet);

	  cupsdLogMessage(CUPSD_LOG_DEBUG2,
	                  "cupsdSendBrowseList: (%d bytes to \"%s\") %s", bytes,
        	          iface->name, packet);

          iface->broadcast.ipv4.sin_port = htons(BrowsePort);

	  sendto(BrowseSocket, packet, bytes, 0,
		 (struct sockaddr *)&(iface->broadcast),
		 httpAddrLength(&(iface->broadcast)));
        }
      }
      else if ((iface = cupsdNetIFFind(b->iface)) != NULL)
      {
       /*
        * Send to the named interface using the IPv4 address...
	*/

        while (iface)
	  if (strcmp(b->iface, iface->name))
	  {
	    iface = NULL;
	    break;
	  }
	  else if (iface->address.addr.sa_family == AF_INET && iface->port)
	    break;
	  else
            iface = (cupsd_netif_t *)cupsArrayNext(NetIFList);

        if (iface)
	{
	  httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
	                   iface->hostname, iface->port,
			   (p->type & CUPS_PRINTER_CLASS) ? "/classes/%s" :
			                                    "/printers/%s",
			   p->name);
	  snprintf(packet, sizeof(packet),
	           "%x %x %s \"%s\" \"%s\" \"%s\" %s%s uuid=%s\n",
        	   type, p->state, uri, location, info, make_model,
		   p->browse_attrs ? p->browse_attrs : "", air, p->uuid);

	  bytes = strlen(packet);

	  cupsdLogMessage(CUPSD_LOG_DEBUG2,
	                  "cupsdSendBrowseList: (%d bytes to \"%s\") %s", bytes,
        	          iface->name, packet);

          iface->broadcast.ipv4.sin_port = htons(BrowsePort);

	  sendto(BrowseSocket, packet, bytes, 0,
		 (struct sockaddr *)&(iface->broadcast),
		 httpAddrLength(&(iface->broadcast)));
        }
      }
    }
    else
    {
     /*
      * Send the browse packet to the indicated address using
      * the default server name...
      */

      snprintf(packet, sizeof(packet),
               "%x %x %s \"%s\" \"%s\" \"%s\" %s%s uuid=%s\n",
       	       type, p->state, p->uri, location, info, make_model,
	       p->browse_attrs ? p->browse_attrs : "", air, p->uuid);

      bytes = strlen(packet);
      cupsdLogMessage(CUPSD_LOG_DEBUG2,
                      "cupsdSendBrowseList: (%d bytes) %s", bytes, packet);

      if (sendto(BrowseSocket, packet, bytes, 0,
		 (struct sockaddr *)&(b->to),
		 httpAddrLength(&(b->to))) <= 0)
      {
       /*
        * Unable to send browse packet, so remove this address from the
	* list...
	*/

	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "cupsdSendBrowseList: sendto failed for browser "
			"%d - %s.",
	                (int)(b - Browsers + 1), strerror(errno));

        if (i > 1)
	  memmove(b, b + 1, (i - 1) * sizeof(cupsd_dirsvc_addr_t));

	b --;
	NumBrowsers --;
      }
    }
}


/*
 * 'update_cups_browse()' - Update the browse lists using the CUPS protocol.
 */

static void
update_cups_browse(void)
{
  int		i;			/* Looping var */
  int		auth;			/* Authorization status */
  int		len;			/* Length of name string */
  int		bytes;			/* Number of bytes left */
  char		packet[1541],		/* Broadcast packet */
		*pptr;			/* Pointer into packet */
  socklen_t	srclen;			/* Length of source address */
  http_addr_t	srcaddr;		/* Source address */
  char		srcname[1024];		/* Source hostname */
  unsigned	address[4];		/* Source address */
  unsigned	type;			/* Printer type */
  unsigned	state;			/* Printer state */
  char		uri[HTTP_MAX_URI],	/* Printer URI */
		host[HTTP_MAX_URI],	/* Host portion of URI */
		resource[HTTP_MAX_URI],	/* Resource portion of URI */
		info[IPP_MAX_NAME],	/* Information string */
		location[IPP_MAX_NAME],	/* Location string */
		make_model[IPP_MAX_NAME];/* Make and model string */
  int		num_attrs;		/* Number of attributes */
  cups_option_t	*attrs;			/* Attributes */


 /*
  * Read a packet from the browse socket...
  */

  srclen = sizeof(srcaddr);
  if ((bytes = recvfrom(BrowseSocket, packet, sizeof(packet) - 1, 0,
                        (struct sockaddr *)&srcaddr, &srclen)) < 0)
  {
   /*
    * "Connection refused" is returned under Linux if the destination port
    * or address is unreachable from a previous sendto(); check for the
    * error here and ignore it for now...
    */

    if (errno != ECONNREFUSED && errno != EAGAIN)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Browse recv failed - %s.",
                      strerror(errno));
      cupsdLogMessage(CUPSD_LOG_ERROR, "CUPS browsing turned off.");

#ifdef WIN32
      closesocket(BrowseSocket);
#else
      close(BrowseSocket);
#endif /* WIN32 */

      cupsdRemoveSelect(BrowseSocket);
      BrowseSocket = -1;

      BrowseLocalProtocols  &= ~BROWSE_CUPS;
      BrowseRemoteProtocols &= ~BROWSE_CUPS;
    }

    return;
  }

  packet[bytes] = '\0';

 /*
  * If we're about to sleep, ignore incoming browse packets.
  */

  if (Sleeping)
    return;

 /*
  * Figure out where it came from...
  */

#ifdef AF_INET6
  if (srcaddr.addr.sa_family == AF_INET6)
  {
    address[0] = ntohl(srcaddr.ipv6.sin6_addr.s6_addr32[0]);
    address[1] = ntohl(srcaddr.ipv6.sin6_addr.s6_addr32[1]);
    address[2] = ntohl(srcaddr.ipv6.sin6_addr.s6_addr32[2]);
    address[3] = ntohl(srcaddr.ipv6.sin6_addr.s6_addr32[3]);
  }
  else
#endif /* AF_INET6 */
  {
    address[0] = 0;
    address[1] = 0;
    address[2] = 0;
    address[3] = ntohl(srcaddr.ipv4.sin_addr.s_addr);
  }

  if (HostNameLookups)
    httpAddrLookup(&srcaddr, srcname, sizeof(srcname));
  else
    httpAddrString(&srcaddr, srcname, sizeof(srcname));

  len = strlen(srcname);

 /*
  * Do ACL stuff...
  */

  if (BrowseACL)
  {
    if (httpAddrLocalhost(&srcaddr) || !_cups_strcasecmp(srcname, "localhost"))
    {
     /*
      * Access from localhost (127.0.0.1) is always allowed...
      */

      auth = CUPSD_AUTH_ALLOW;
    }
    else
    {
     /*
      * Do authorization checks on the domain/address...
      */

      switch (BrowseACL->order_type)
      {
        default :
	    auth = CUPSD_AUTH_DENY;	/* anti-compiler-warning-code */
	    break;

	case CUPSD_AUTH_ALLOW : /* Order Deny,Allow */
            auth = CUPSD_AUTH_ALLOW;

            if (cupsdCheckAuth(address, srcname, len, BrowseACL->deny))
	      auth = CUPSD_AUTH_DENY;

            if (cupsdCheckAuth(address, srcname, len, BrowseACL->allow))
	      auth = CUPSD_AUTH_ALLOW;
	    break;

	case CUPSD_AUTH_DENY : /* Order Allow,Deny */
            auth = CUPSD_AUTH_DENY;

            if (cupsdCheckAuth(address, srcname, len, BrowseACL->allow))
	      auth = CUPSD_AUTH_ALLOW;

            if (cupsdCheckAuth(address, srcname, len, BrowseACL->deny))
	      auth = CUPSD_AUTH_DENY;
	    break;
      }
    }
  }
  else
    auth = CUPSD_AUTH_ALLOW;

  if (auth == CUPSD_AUTH_DENY)
  {
    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "update_cups_browse: Refused %d bytes from %s", bytes,
                    srcname);
    return;
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "update_cups_browse: (%d bytes from %s) %s", bytes,
		  srcname, packet);

 /*
  * Parse packet...
  */

  if (sscanf(packet, "%x%x%1023s", &type, &state, uri) < 3)
  {
    cupsdLogMessage(CUPSD_LOG_WARN,
                    "update_cups_browse: Garbled browse packet - %s", packet);
    return;
  }

  strcpy(location, "Location Unknown");
  strcpy(info, "No Information Available");
  make_model[0] = '\0';
  num_attrs     = 0;
  attrs         = NULL;

  if ((pptr = strchr(packet, '\"')) != NULL)
  {
   /*
    * Have extended information; can't use sscanf for it because not all
    * sscanf's allow empty strings with %[^\"]...
    */

    for (i = 0, pptr ++;
         i < (sizeof(location) - 1) && *pptr && *pptr != '\"';
         i ++, pptr ++)
      location[i] = *pptr;

    if (i)
      location[i] = '\0';

    if (*pptr == '\"')
      pptr ++;

    while (*pptr && isspace(*pptr & 255))
      pptr ++;

    if (*pptr == '\"')
    {
      for (i = 0, pptr ++;
           i < (sizeof(info) - 1) && *pptr && *pptr != '\"';
           i ++, pptr ++)
	info[i] = *pptr;

      info[i] = '\0';

      if (*pptr == '\"')
	pptr ++;

      while (*pptr && isspace(*pptr & 255))
	pptr ++;

      if (*pptr == '\"')
      {
	for (i = 0, pptr ++;
             i < (sizeof(make_model) - 1) && *pptr && *pptr != '\"';
             i ++, pptr ++)
	  make_model[i] = *pptr;

	if (*pptr == '\"')
	  pptr ++;

	make_model[i] = '\0';

        if (*pptr)
	  num_attrs = cupsParseOptions(pptr, num_attrs, &attrs);
      }
    }
  }

  DEBUG_puts(packet);
  DEBUG_printf(("type=%x, state=%x, uri=\"%s\"\n"
                "location=\"%s\", info=\"%s\", make_model=\"%s\"\n",
	        type, state, uri, location, info, make_model));

 /*
  * Pull the URI apart to see if this is a local or remote printer...
  */

  if (is_local_queue(uri, host, sizeof(host), resource, sizeof(resource)))
  {
    cupsFreeOptions(num_attrs, attrs);
    return;
  }

 /*
  * Do relaying...
  */

  for (i = 0; i < NumRelays; i ++)
    if (cupsdCheckAuth(address, srcname, len, Relays[i].from))
      if (sendto(BrowseSocket, packet, bytes, 0,
                 (struct sockaddr *)&(Relays[i].to),
		 httpAddrLength(&(Relays[i].to))) <= 0)
      {
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "update_cups_browse: sendto failed for relay %d - %s.",
	                i + 1, strerror(errno));
	cupsFreeOptions(num_attrs, attrs);
	return;
      }

 /*
  * Process the browse data...
  */

  process_browse_data(uri, host, resource, (cups_ptype_t)type,
                      (ipp_pstate_t)state, location, info, make_model,
		      num_attrs, attrs);
}


/*
 * 'update_lpd()' - Update the LPD configuration as needed.
 */

static void
update_lpd(int onoff)			/* - 1 = turn on, 0 = turn off */
{
  if (!LPDConfigFile)
    return;

#ifdef __APPLE__
 /*
  * Allow /etc/hostconfig CUPS_LPD service setting to override cupsd.conf
  * setting for backwards-compatibility.
  */

  if (onoff && !get_hostconfig("CUPS_LPD"))
    onoff = 0;
#endif /* __APPLE__ */

  if (!strncmp(LPDConfigFile, "xinetd:///", 10))
  {
   /*
    * Enable/disable LPD via the xinetd.d config file for cups-lpd...
    */

    char	newfile[1024];		/* New cups-lpd.N file */
    cups_file_t	*ofp,			/* Original file pointer */
		*nfp;			/* New file pointer */
    char	line[1024];		/* Line from file */


    snprintf(newfile, sizeof(newfile), "%s.N", LPDConfigFile + 9);

    if ((ofp = cupsFileOpen(LPDConfigFile + 9, "r")) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to open \"%s\" - %s",
                      LPDConfigFile + 9, strerror(errno));
      return;
    }

    if ((nfp = cupsFileOpen(newfile, "w")) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to create \"%s\" - %s",
                      newfile, strerror(errno));
      cupsFileClose(ofp);
      return;
    }

   /*
    * Copy all of the lines from the cups-lpd file...
    */

    while (cupsFileGets(ofp, line, sizeof(line)))
    {
      if (line[0] == '{')
      {
        cupsFilePrintf(nfp, "%s\n", line);
        snprintf(line, sizeof(line), "\tdisable = %s",
	         onoff ? "no" : "yes");
      }
      else if (!strstr(line, "disable ="))
        cupsFilePrintf(nfp, "%s\n", line);
    }

    cupsFileClose(nfp);
    cupsFileClose(ofp);
    rename(newfile, LPDConfigFile + 9);
  }
#ifdef __APPLE__
  else if (!strncmp(LPDConfigFile, "launchd:///", 11))
  {
   /*
    * Enable/disable LPD via the launchctl command...
    */

    char	*argv[5],		/* Arguments for command */
		*envp[MAX_ENV];		/* Environment for command */
    int		pid;			/* Process ID */


    cupsdLoadEnv(envp, (int)(sizeof(envp) / sizeof(envp[0])));
    argv[0] = (char *)"launchctl";
    argv[1] = (char *)(onoff ? "load" : "unload");
    argv[2] = (char *)"-w";
    argv[3] = LPDConfigFile + 10;
    argv[4] = NULL;

    cupsdStartProcess("/bin/launchctl", argv, envp, -1, -1, -1, -1, -1, 1,
                      NULL, NULL, &pid);
  }
#endif /* __APPLE__ */
  else
    cupsdLogMessage(CUPSD_LOG_INFO, "Unknown LPDConfigFile scheme!");
}


/*
 * 'update_polling()' - Read status messages from the poll daemons.
 */

static void
update_polling(void)
{
  char		*ptr,			/* Pointer to end of line in buffer */
		message[1024];		/* Pointer to message text */
  int		loglevel;		/* Log level for message */


  while ((ptr = cupsdStatBufUpdate(PollStatusBuffer, &loglevel,
                                   message, sizeof(message))) != NULL)
  {
    if (loglevel == CUPSD_LOG_INFO)
      cupsdLogMessage(CUPSD_LOG_INFO, "%s", message);

    if (!strchr(PollStatusBuffer->buffer, '\n'))
      break;
  }

  if (ptr == NULL && !PollStatusBuffer->bufused)
  {
   /*
    * All polling processes have died; stop polling...
    */

    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "update_polling: all polling processes have exited!");
    cupsdStopPolling();
  }
}


/*
 * 'update_smb()' - Update the SMB configuration as needed.
 */

static void
update_smb(int onoff)			/* I - 1 = turn on, 0 = turn off */
{
  if (!SMBConfigFile)
    return;

  if (!strncmp(SMBConfigFile, "samba:///", 9))
  {
   /*
    * Enable/disable SMB via the specified smb.conf config file...
    */

    char	newfile[1024];		/* New smb.conf.N file */
    cups_file_t	*ofp,			/* Original file pointer */
		*nfp;			/* New file pointer */
    char	line[1024];		/* Line from file */
    int		in_printers;		/* In [printers] section? */


    snprintf(newfile, sizeof(newfile), "%s.N", SMBConfigFile + 8);

    if ((ofp = cupsFileOpen(SMBConfigFile + 8, "r")) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to open \"%s\" - %s",
                      SMBConfigFile + 8, strerror(errno));
      return;
    }

    if ((nfp = cupsFileOpen(newfile, "w")) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to create \"%s\" - %s",
                      newfile, strerror(errno));
      cupsFileClose(ofp);
      return;
    }

   /*
    * Copy all of the lines from the smb.conf file...
    */

    in_printers = 0;

    while (cupsFileGets(ofp, line, sizeof(line)))
    {
      if (in_printers && strstr(line, "printable ="))
        snprintf(line, sizeof(line), "    printable = %s",
	         onoff ? "yes" : "no");

      cupsFilePrintf(nfp, "%s\n", line);

      if (line[0] == '[')
        in_printers = !strcmp(line, "[printers]");
    }

    cupsFileClose(nfp);
    cupsFileClose(ofp);
    rename(newfile, SMBConfigFile + 8);
  }
  else
    cupsdLogMessage(CUPSD_LOG_INFO, "Unknown SMBConfigFile scheme!");
}


/*
 * End of "$Id: dirsvc.c 10472 2012-05-18 02:25:18Z mike $".
 */
