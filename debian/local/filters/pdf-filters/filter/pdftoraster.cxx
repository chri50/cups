/*
Copyright (c) 2008, BBR Inc.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
/*
 pdftoraster.cc
 pdf to raster filter
*/

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "goo/GooString.h"
#include "goo/gmem.h"
#include "Object.h"
#include "Stream.h"
#include "PDFDoc.h"
#include "SplashOutputDev.h"
#include <cups/cups.h>
#include <stdarg.h>
#include "Error.h"
#include "GlobalParams.h"
#include "raster.h"
#include <splash/SplashTypes.h>
#include <splash/SplashBitmap.h>

#define MAX_CHECK_COMMENT_LINES	20

namespace {
  int exitCode = 0;
  int deviceCopies = 1;
  bool deviceCollate = false;
  cups_page_header2_t header2;
  cups_page_header_t header;
};

void CDECL myErrorFun(int pos, char *msg, va_list args)
{
  if (pos >= 0) {
    fprintf(stderr, "ERROR (%d): ", pos);
  } else {
    fprintf(stderr, "ERROR: ");
  }
  vfprintf(stderr, msg, args);
  fprintf(stderr, "\n");
  fflush(stderr);
}

void parseOpts(int argc, char **argv)
{
  int num_options = 0;
  cups_option_t *options = 0;
  ppd_file_t *ppd = 0;

  if (argc < 6 || argc > 7) {
    error(-1,"%s job-id user title copies options [file]",
      argv[0]);
    exit(1);
  }

  ppd = ppdOpenFile(getenv("PPD"));
  ppdMarkDefaults(ppd);
  options = NULL;
  num_options = cupsParseOptions(argv[5],0,&options);
  cupsMarkOptions(ppd,num_options,options);
  cupsRasterInterpretPPD(&header2,ppd,num_options,options,0);
  memcpy(&header,&header2,sizeof(header));
}

void parsePDFTOPDFComment(FILE *fp)
{
  char buf[4096];
  int i;

  /* skip until PDF start header */
  while (fgets(buf,sizeof(buf),fp) != 0) {
    if (strncmp(buf,"%PDF",4) == 0) {
      break;
    }
  }
  for (i = 0;i < MAX_CHECK_COMMENT_LINES;i++) {
    if (fgets(buf,sizeof(buf),fp) == 0) break;
    if (strncmp(buf,"%%PDFTOPDFNumCopies",19) == 0) {
      char *p;

      p = strchr(buf+19,':');
      deviceCopies = atoi(p+1);
    } else if (strncmp(buf,"%%PDFTOPDFCollate",17) == 0) {
      char *p;

      p = strchr(buf+17,':');
      while (*p == ' ' || *p == '\t') p++;
      if (strncasecmp(p,"true",4) == 0) {
	deviceCollate = true;
      } else {
	deviceCollate = false;
      }
    }
  }
}

int main(int argc, char *argv[]) {
  PDFDoc *doc;
  SplashOutputDev *out;
  SplashColor paperColor;
  int i;
  int npages;
  cups_raster_t *raster;
  enum SplashColorMode cmode;
  int rowpad;
  GBool reverseVideo;

  setErrorFunction(::myErrorFun);
#ifdef GLOBALPARAMS_HAS_A_ARG
  globalParams = new GlobalParams(0);
#else
  globalParams = new GlobalParams();
#endif
  parseOpts(argc, argv);

  if (argc == 6) {
    /* stdin */
    int fd;
    Object obj;
    BaseStream *str;
    FILE *fp;
    char buf[BUFSIZ];
    int n;

    fd = cupsTempFd(buf,sizeof(buf));
    if (fd < 0) {
      error(-1,"Can't create temporary file");
      exit(1);
    }
    /* remove name */
    unlink(buf);

    /* copy stdin to the tmp file */
    while ((n = read(0,buf,BUFSIZ)) > 0) {
      if (write(fd,buf,n) != n) {
        error(-1,"Can't copy stdin to temporary file");
        close(fd);
	exit(1);
      }
    }
    if (lseek(fd,0,SEEK_SET) < 0) {
        error(-1,"Can't rewind temporary file");
        close(fd);
	exit(1);
    }

    if ((fp = fdopen(fd,"rb")) == 0) {
        error(-1,"Can't fdopen temporary file");
        close(fd);
	exit(1);
    }

    obj.initNull();
    parsePDFTOPDFComment(fp);
    rewind(fp);
    str = new FileStream(fp,0,gFalse,0,&obj);
    doc = new PDFDoc(str);
  } else {
    GooString *fileName = new GooString(argv[6]);
    /* argc == 7 filenmae is specified */
    FILE *fp;

    if ((fp = fopen(argv[6],"rb")) == 0) {
        error(-1,"Can't open input file %s",argv[6]);
	exit(1);
    }
    parsePDFTOPDFComment(fp);
    fclose(fp);
    doc = new PDFDoc(fileName,NULL,NULL);
  }

  if (!doc->isOk()) {
    exitCode = 1;
    goto err1;
  }

  /* fix NumCopies, Collate ccording to PDFTOPDFComments */
  header.NumCopies = deviceCopies;
  header.Collate = deviceCollate ? CUPS_TRUE : CUPS_FALSE;
  /* fixed other values that pdftopdf handles */
  header.MirrorPrint = CUPS_FALSE;
  header.Orientation = CUPS_ORIENT_0;

  /* set image's values */
  reverseVideo = gFalse;
  switch (header.cupsColorSpace) {
  case CUPS_CSPACE_RGB:
    if (header.cupsColorOrder != CUPS_ORDER_CHUNKED
       || header.cupsBitsPerColor != 8
       || header.cupsBitsPerPixel != 24) {
      error(-1,"Specified color format is not supported");
      exit(1);
    }
    cmode = splashModeRGB8;
    rowpad = 4;
    /* set paper color white */
    paperColor[0] = 255;
    paperColor[1] = 255;
    paperColor[2] = 255;
    break;
  case CUPS_CSPACE_K:
    reverseVideo = gTrue;
  case CUPS_CSPACE_W:
    if (header.cupsColorOrder != CUPS_ORDER_CHUNKED) {
      error(-1,"Specified color format is not supported");
      exit(1);
    }
    if (header.cupsBitsPerColor == 1 
       && header.cupsBitsPerPixel == 1) {
      cmode = splashModeMono1;
    } else if (header.cupsBitsPerColor == 8
       && header.cupsBitsPerPixel == 8) {
      cmode = splashModeMono8;
    } else {
      error(-1,"Specified color format is not supported");
      exit(1);
    }
    /* set paper color white */
    paperColor[0] = 255;
    rowpad = 1;
    break;
#ifdef SPLASH_CMYK
  case CUPS_CSPACE_CMYK:
    if (header.cupsColorOrder != CUPS_ORDER_CHUNKED
       || header.cupsBitsPerColor != 8
       || header.cupsBitsPerPixel != 32) {
      error(-1,"Specified color format is not supported");
      exit(1);
    }
    cmode = splashModeCMYK8;
    /* set paper color white */
    paperColor[0] = 0;
    paperColor[1] = 0;
    paperColor[2] = 0;
    paperColor[3] = 0;
    rowpad = 4;
    break;
#endif
  default:
    error(-1,"Specified ColorSpace is not supported");
    exit(1);
    break;
  }


  out = new SplashOutputDev(cmode,rowpad/* row padding */,
    reverseVideo,paperColor,gTrue,gFalse);
  out->startDoc(doc->getXRef());

  if ((raster = cupsRasterOpen(1,CUPS_RASTER_WRITE)) == 0) {
        error(-1,"Can't open raster stream");
	exit(1);
  }
  npages = doc->getNumPages();
  for (i = 1;i <= npages;i++) {
    SplashBitmap *bitmap;
    unsigned int size;

    doc->displayPage(out,i,header.HWResolution[0],
      header.HWResolution[1],0,gFalse,gFalse,gFalse);
    bitmap = out->getBitmap();

    /* write page header */
    header.cupsWidth = bitmap->getWidth();
    header.cupsHeight = bitmap->getHeight();
    header.cupsBytesPerLine = bitmap->getRowSize();
    if (!cupsRasterWriteHeader(raster,&header)) {
        error(-1,"Can't write page %d header",i);
	exit(1);
    }

    /* write page image */
    size = bitmap->getRowSize()*bitmap->getHeight();
    if (cupsRasterWritePixels(raster,(unsigned char *)(bitmap->getDataPtr()),
         size) != size) {
        error(-1,"Can't write page %d image",i);
	exit(1);
    }
  }
  cupsRasterClose(raster);

  delete out;
err1:
  delete doc;

  // Check for memory leaks
  Object::memCheck(stderr);
  gMemReport(stderr);

  return exitCode;
}

/* replace memory allocation methods for memory check */

void * operator new(size_t size)
{
  return gmalloc(size);
}

void operator delete(void *p)
{
  gfree(p);
}

void * operator new[](size_t size)
{
  return gmalloc(size);
}

void operator delete[](void *p)
{
  gfree(p);
}
