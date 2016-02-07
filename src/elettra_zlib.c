#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "elettra.h"

unsigned char *
elettra_gzip (FILE * in, int *finlen, struct elettra_stream *es)
{
  const char *zmode = "wb9h";
  unsigned char *comprblock;
  struct stat st;
  gzFile tmpgz;
  caddr_t addrbuf;
  int size, infd = fileno (in);
  FILE *binput;

  tmpgz = gzopen (es->outfname, zmode);
  fstat (infd, &st);

  addrbuf =
    mmap ((caddr_t) 0, st.st_size, PROT_READ, MAP_SHARED, infd, (off_t) 0);

  size = gzwrite (tmpgz, (unsigned char *) addrbuf, st.st_size);

  munmap (addrbuf, st.st_size);
  gzclose (tmpgz);

  stat (es->outfname, &st);
  binput = fopen (es->outfname, "rb");
  comprblock = malloc (st.st_size);

  fread (comprblock, st.st_size, 1, binput);
  fclose (binput);

  *finlen = st.st_size;
  return comprblock;
}

int
elettra_ungzip (char *gzsource)
{
#define BUFBLOCK	4096
  char *tempdump, buf[BUFBLOCK];
  gzFile zin;
  FILE *outmp;
  int len;

  tempdump = malloc (strlen (gzsource) + 6);
  sprintf (tempdump, "%s.tmp", gzsource);

  if ((outmp = fopen (tempdump, "w+")) == NULL)
    {
      fprintf (stderr, "unable to open tempfile %s: %s\n",
	       tempdump, strerror (errno));
      return -1;
    }
  zin = gzopen (gzsource, "rb");

  do
    {
      if ((len = gzread (zin, buf, BUFBLOCK)) < 0)
	{
	  fprintf (stderr, "error in decompression");
	  return -1;
	}
      if (fwrite (buf, 1, len, outmp) != len)
	{
	  fprintf (stderr, "unable to write in %s: %s\n",
		   tempdump, strerror (errno));
	  return -1;
	}
    }
  while (len != 0);

  fclose (outmp);
  gzclose (zin);

  rename (tempdump, gzsource);

  return 0;
}
