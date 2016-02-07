#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <mhash.h>
#include <mcrypt.h>

#include "elettra.h"

#define e_rand(min, max) ((rand() % (int)(((max)+1) - (min))) + (min))

static char *basename (const char *file);

/* EXPORTED FUNCTION, for elettra.c */
int
elettra_init (struct elettra_stream *es)
{
  struct timeval randinit;
  unsigned char random_block[256];
  int i;
  FILE *randfd;

  es->crypto_engine = mcrypt_module_open ("rijndael-128", NULL, "cbc", NULL);
  es->ivsize = mcrypt_enc_get_iv_size (es->crypto_engine);
  es->keysize = mcrypt_enc_get_key_size (es->crypto_engine);
  es->IV = malloc (es->ivsize);
  es->key = malloc (es->keysize);

  if((randfd =fopen("/dev/urandom", "r")) ==NULL)
  {
     snprintf (es->error, ELEN, "unable to open /dev/urandom: %s\n", strerror(errno));
     return -ELET_INIT_INTERNAL;
  }
  fread(random_block, 256, 1, randfd);
  fclose(randfd);

  gettimeofday (&randinit, NULL);
  srand ( randinit.tv_usec ^ randinit.tv_sec );

  for(i =0; i < 256; i++)
    srand( rand() ^ random_block[i] );

  return 0;
}

int
get_percentage (int ac, const char **av, struct elettra_stream *es)
{
  if (av[3][strlen (av[3]) - 1] == '%')
    {
      char *prcstr = strdup (av[3]);
      int prclen = strlen (av[3]);

      prcstr[prclen - 1] = 0x00;	/* strip '%' */
      es->percent_payload = atoi (prcstr);

      if (es->percent_payload < 10 || es->percent_payload > 1000)
	{
	  snprintf (es->error, ELEN,
		    "%s: percentage must be since 10%% to 1000%%, default %d%%\n",
		    av[4], DEFAULT_PERCENT_PAYLOAD);
	  return -1;
	}
      free (prcstr);
      return 4;			/* the addictional files start since argv[4] */
    }
  else
    {
      es->percent_payload = DEFAULT_PERCENT_PAYLOAD;
      return 3;			/* the addictional files start since argv[3]
				 * because the percentage are used as default
				 * value */
    }
}


/* open, compress and fix the elettra_fileformat struct for the 'fname' file */
int
acquire_file (const char *fname, struct elettra_stream *es)
{
  FILE *input;
  struct elettra_fileformat *new;

  /* check fname and its permissions */
  if ((input = fopen (fname, "r")) == NULL)
    {
      snprintf (es->error, ELEN, "unable to open %s: %s", fname,
		strerror (errno));
      return -1;
    }
  es->source_files++;
  es->comprf =
    realloc (es->comprf,
	     sizeof (struct elettra_fileformat) * es->source_files);

  new = &(es->comprf[es->source_files - 1]);

  memset (new, 0x00, sizeof (struct elettra_fileformat));

  /* duplicate filename and check basename */
  new->fname = basename (fname);
  new->fname_len = strlen (new->fname);

  /*
   * starting compression, using the file_compress in minigzip.c in
   * zlib documentation, this should be improvered without swap in the
   * disk.
   * 
   * function implementaed in elettra_zlib.c
   */
  if ((new->compr_data = elettra_gzip (input, &new->compr_len, es)) == NULL)
    {
      snprintf (es->error, ELEN, "unable to compress %s", fname);
      return -1;
    }
  /*
   * the checksum (present in elettra_fileformat), is related to the
   * key, and is set before the encryption
   */
  return 0;
}

static int
get_hdr_data_size (struct elettra_fileformat ef)
{
  return (ef.compr_len + ef.fname_len + (sizeof (int) * 4));
}

int
alloc_internal_array (struct elettra_stream *es)
{
  int i, max_padding = 0, prcnt, size, last_used_offset = 0;

  /* checksum, length, file length, random */
  if ((es->epo =
       calloc (es->source_files, sizeof (struct elettra_po))) == NULL)
    {
      snprintf (es->error, ELEN, "calloc: %s", strerror (errno));
      return -1;
    }
  for (i = 0; i < es->source_files; i++)
    {
      /* for each file check the possible padding percentage */
      int lazyrand = e_rand (1, 4);

      /* size is compressed data + header */
      size = get_hdr_data_size (es->comprf[i]);
      size = ((size / mcrypt_enc_get_block_size (es->crypto_engine)) + 1);
      size *= mcrypt_enc_get_block_size (es->crypto_engine);

      /* the user must not have the total control on random padding */
      switch (lazyrand)
	{
	case 1:
	  max_padding = (size * es->percent_payload) / 100;
	  break;
	case 2:
	  prcnt = 1 + es->percent_payload - (e_rand (1, es->percent_payload));
	  max_padding = (size * prcnt) / 100;
	  break;
	case 3:
	  max_padding = ((size / 5) * es->percent_payload) / 100;
	  break;
	case 4:
	  max_padding =
	    (size * (es->percent_payload + e_rand (20, 40))) / 100;
	  break;
	default:		/* never happens */
	  break;
	}
      /*
       * but the algoritm is strong because is real random. if you
       * don't like a file size, re-run elettra
       */

      /* this padding exists to assure a minimum random every file */
      max_padding += mcrypt_enc_get_block_size (es->crypto_engine);

      (es->epo[i]).min_ep = last_used_offset;
      (es->epo[i]).max_ep = last_used_offset + max_padding;

      /*
       * padding + header + data, the blob is written in
       * elettra_final_write
       */

      last_used_offset += max_padding + size;
    }

  es->finalsize = (last_used_offset + es->header_length);

  return 0;
}

int
search_passwords (struct elettra_stream *es)
{
  unsigned char bruteforce[KEYLEN];
  int i, k, entry_point;

  for (i = 0; i < MAX_BRUTEFORCE_TRY; i++)
    {

      /* 
       * we must randomize, otherwise, once disclosed a password you
       * should crack the keys near the know key, for this reason
       * I didn't use an incremental algo of password research 
       */
      fill_me_with_entropy (bruteforce, KEYLEN);

      entry_point = get_hash_ep (bruteforce, KEYLEN, es->finalsize);

      for (k = 0; k < es->source_files; k++)
	{
	  if ((es->epo[k]).internal_key == NULL)
	    {
	      if (entry_point >= (es->epo[k]).min_ep
		  && entry_point <= (es->epo[k]).max_ep)
		{
		  es->epo[k].entry_point = entry_point;
		  es->epo[k].internal_key = malloc (KEYLEN);
		  memcpy (es->epo[k].internal_key, bruteforce, KEYLEN);
		  es->epo[k].post_padding = (es->epo[k]).max_ep - entry_point;
		  return 1;
		}
	    }
	}
    }

  return 0;
}

int
elettra_final_write (struct elettra_stream *es)
{
  int i, last_used_offset = 0;

  for (i = 0; i < es->source_files; i++)
    {
      unsigned char *data;
      int entropy_needed, ptr = 0, size = 0;

      /*
       * pre padding, hash functions are implemented in
       * elettra_utils.c
       */
      entropy_needed = ((es->epo[i]).entry_point - last_used_offset);

      if (entropy_needed)
	{
	  if ((data = malloc (entropy_needed)) == NULL)
	    {
	      snprintf (es->error, ELEN, "malloc %d: %s",
			entropy_needed, strerror (errno));
	      return -1;
	    }
	  fill_me_with_entropy (data, entropy_needed);

	  if (fwrite (data, 1, entropy_needed, es->output) != entropy_needed)
	    {
	      snprintf (es->error, ELEN, "fwrite random data: %d byte %s",
			entropy_needed, strerror (errno));
	      return -1;
	    }
	  free (data);

	  last_used_offset += entropy_needed;
	}
      size = get_hdr_data_size (es->comprf[i]);
      /*
       * expand data size for alignment with minimum encryption
       * block
       */
      size = ((size / mcrypt_enc_get_block_size (es->crypto_engine)) + 1);
      size *= mcrypt_enc_get_block_size (es->crypto_engine);

      memset (es->key, 0x00, es->keysize);
      memset (es->IV, 0x00, es->ivsize);

      /* set_password_hash in elettra_utils.c */
      set_password_hash (es->key, es->keysize, es->IV, es->ivsize,
			 (es->epo[i]).internal_key, KEYLEN);
      /*
       * finds a password checksum to determine if the password is
       * right. (checked at decryption time)
       */
      es->comprf[i].key_sum =
	elettra_key_checksum (es->key, es->keysize);

      /*
       * size is compensive of random padding after the compressed
       * file. the non-initialized-memory is encrypted too, to
       * protect against statistical analysis
       */
      data = malloc (size);

      memcpy (&data[ptr], &((es->comprf[i]).key_sum), sizeof (int));
      ptr = sizeof (int);
      memcpy (&data[ptr], &((es->comprf[i]).compr_len), sizeof (int));
      ptr += sizeof (int);
      memcpy (&data[ptr], (es->comprf[i]).compr_data,
	      (es->comprf[i]).compr_len);
      ptr += (es->comprf[i]).compr_len;
      memcpy (&data[ptr], &((es->comprf[i]).fname_len), sizeof (int));
      ptr += sizeof (int);
      memcpy (&data[ptr], (es->comprf[i]).fname, (es->comprf[i]).fname_len);
      ptr += (es->comprf[i]).fname_len;

      /* let's start encryption, initialized with password before */
      mcrypt_generic_init (es->crypto_engine, es->key, es->keysize, es->IV);
      if (mcrypt_generic (es->crypto_engine, data, size))
	{
	  snprintf (es->error, ELEN, "error crypting %d byte", size);
	  return -1;
	}
      mcrypt_generic_deinit (es->crypto_engine);

      /* write encrypted elettra_fileformat + data + fname */
      if (fwrite (data, 1, size, es->output) != size)
	{
	  snprintf (es->error, ELEN, "unable to write data %d byte %s",
		    size, strerror (errno));
	  return -1;
	}
      free (data);

      last_used_offset += size;

      if ((es->epo[i]).post_padding)
	{
	  if ((data = malloc ((es->epo[i]).post_padding)) == NULL)
	    {
	      snprintf (es->error, ELEN, "malloc %d: %s",
			entropy_needed, strerror (errno));
	      return -1;
	    }
	  fill_me_with_entropy (data, (es->epo[i]).post_padding);
	  if (fwrite (data, 1, (es->epo[i]).post_padding, es->output) !=
	      (es->epo[i]).post_padding)
	    {
	      snprintf (es->error, ELEN,
			"fwrite post padding data: %d byte %s",
			(es->epo[i]).post_padding, strerror (errno));
	      return -1;
	    }
	  free (data);

	  last_used_offset += (es->epo[i]).post_padding;
	}
      /*
       * and the next padding fills the difference between my
       * entry_poing + size to the next entry_point
       */
    }

  return 0;
}

static char *
basename (const char *file)
{
#ifndef WIN32
  char *base;

  if ((base = strrchr (file, '/')))
    return strdup (base + 1);

  return strdup (file);
#else
  char *base;

  if ((base = strrchr (file, '\\')))
    return strdup (base + 1);

  if (((file[0] >= 'A' && file[0] <= 'Z') ||
       (file[0] >= 'a' && file[0] <= 'z')) && file[1] == ':')
    return strdup (file + 2);

  return strdup (file);
#endif
}
