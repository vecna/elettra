#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "elettra.h"

int
check_password_hdr (char **passlist, int passnumber)
{
  unsigned char *testinit;
  int i;
  int random_happens;
  int block_size;

  srand ((unsigned int) &random_happens + rand ());
  random_happens = (rand () % AVAILABLE_INITBSIZE);
  block_size = STARTBLOCKSIZE + (random_happens * STEPBLOCKSIZE);

  if (passnumber > WHEN_RANDOM_IS_HOPELESS)
    {
      block_size += ((passnumber - WHEN_RANDOM_IS_HOPELESS) * STEPBLOCKSIZE);
    }

  testinit = malloc (block_size);
  memset (testinit, 0x00, block_size);

  for (i = 0; i < passnumber; i++)
    {
      int fall;

      fall = get_hash_ep ((unsigned char *)passlist[i], strlen (passlist[i]),
			  block_size - sizeof (struct password_block));

      /* bad password, or header length, because our hash collide with another */
      if (testinit[fall] == 0xff)
	{
	  free (testinit);
	  return 0;
	}

      /* we mark memory for check if collision should survive */
      memset (&testinit[fall], 0xff, sizeof (struct password_block));
    }

  free (testinit);

  return block_size;
}

int
extract_key (unsigned char *extracted_key, FILE * in, char *p)
{
  struct password_block passblock;
  MCRYPT decrypt_engine;
  int i, ret, ivsize, keysize;
  char *tryblock;
  int block_size, pass_checksum;
  unsigned char *key, *IV;

  decrypt_engine = mcrypt_module_open ("rijndael-128", NULL, "cbc", NULL);

  ivsize = mcrypt_enc_get_iv_size (decrypt_engine);
  keysize = mcrypt_enc_get_key_size (decrypt_engine);
  IV = malloc (ivsize);
  key = malloc (keysize);

  set_password_hash (key, keysize, IV, ivsize, (unsigned char *)p, strlen (p));

  for (i = 0; i < TRY_LOOK_AT_KEYBLOCK; i++)
    {
      int fall;

      block_size = STARTBLOCKSIZE + (i * STEPBLOCKSIZE);
      tryblock = malloc (block_size);

      ret = fread (tryblock, 1, block_size, in);

      if (ret != block_size)
	{
	  fprintf (stderr,
		   "error in read input file while looking keyblock of %d bytes\n",
		   block_size);
	  return -1;
	}

      rewind (in);

      fall =
	get_hash_ep ((unsigned char *)p, strlen (p),
		     block_size - sizeof (struct password_block));
      memcpy ((void *) &passblock, &(tryblock[fall]),
	      sizeof (struct password_block));

      mcrypt_generic_init (decrypt_engine, key, keysize, IV);
      set_password_hash (key, keysize, IV, ivsize, (unsigned char *)p, strlen (p));

      /* decrypt the block for password_block size */
      mdecrypt_generic (decrypt_engine, (void *) &passblock,
			sizeof (struct password_block));
      pass_checksum = elettra_key_checksum (key, keysize);
      mcrypt_generic_deinit (decrypt_engine);

      if (pass_checksum == passblock.checksum)
	{
	  memcpy (extracted_key, passblock.internal_key, KEYLEN);
	  return block_size;
	}
    }

  free (IV);
  free (key);

  return -1;
}

int
import_password (int ac, const char **av, struct elettra_stream *es,
		 int first_file_arg)
{
  int i;
  struct stat st;

  /* format: file1::password1 fileN::passwordN */
  for (i = first_file_arg; i < ac; i++)
    {
      char *p;

      es->file_number++;

      es->passlist =
	realloc (es->passlist, sizeof (char *) * es->file_number);
      es->ft = realloc (es->ft, sizeof (struct filetrack) * es->file_number);

      p = strstr (av[i], "::");

      if (p != NULL)
	{
	  char *dup_p;

	  es->ft[(es->file_number - 1)].fname = strdup (av[i]);
	  dup_p = strstr (es->ft[(es->file_number - 1)].fname, "::");
	  *dup_p = 0x00;

	  dup_p += strlen ("::");
	  es->passlist[(es->file_number - 1)] = strdup (dup_p);
	}
      else
	{
	  es->ft[(es->file_number - 1)].fname = strdup (av[i]);
	  es->passlist[(es->file_number - 1)] = NULL;
	}

      if (stat (es->ft[(es->file_number - 1)].fname, &st) == -1)
	{
	  snprintf (es->error, ELEN, "file [%s] error on stat: %s",
		    es->ft[(es->file_number - 1)].fname, strerror (errno));
	  return -ELET_INVALID_FILE;
	}
      else
	{
	  memcpy (&(es->ft[(es->file_number - 1)].st), &st,
		  sizeof (struct stat));
	}
    }

  for (i = 0; i < es->file_number; i++)
    {
      char *pass, buf[1024];

      if (es->passlist[i] == NULL)
	{
	  snprintf (buf, 1024, "insert password for %s: ", es->ft[i].fname);
	  pass = getpass (buf);

          es->passlist[i] = strdup(pass);
	}

      /* check password length for command line & terminal password */
      if (strlen (es->passlist[i]) < MINLENPASS)
	{
	  snprintf (es->error, ELEN,
		    "file %s had short password (min %d bytes)",
		    es->ft[i].fname, MINLENPASS);
	  return -ELET_PASSSHORT;
	}

      /* copy password for file track struct */
      es->ft[i].password = strdup (es->passlist[i]);

    }

  return 0;
}

int
elettra_header_write (struct elettra_stream *es)
{
  struct password_block pblock;
  unsigned char *header;
  MCRYPT block_engine;
  unsigned char *IV, *key;
  int i, keysize, ivsize;

  header = malloc (es->header_length);
  fill_me_with_entropy (header, es->header_length);

  block_engine = mcrypt_module_open ("rijndael-128", NULL, "cbc", NULL);
  ivsize = mcrypt_enc_get_iv_size (block_engine);
  keysize = mcrypt_enc_get_key_size (block_engine);
  IV = malloc (es->ivsize);
  key = malloc (es->keysize);

  for (i = 0; i < es->file_number; i++)
    {
      int fall;

      fall = get_hash_ep ((unsigned char *)es->passlist[i], strlen (es->passlist[i]),
			  es->header_length - sizeof (struct password_block));

      set_password_hash (key, keysize, IV, ivsize, (unsigned char *)es->passlist[i],
			 strlen (es->passlist[i]));

      memcpy (pblock.internal_key, (es->epo[i]).internal_key, KEYLEN);
      pblock.checksum = elettra_key_checksum (key, keysize);

      mcrypt_generic_init (block_engine, key, keysize, IV);
      if (mcrypt_generic (block_engine, &pblock, sizeof (pblock)))
	{
	  snprintf (es->error, ELEN, "error crypting header");
	  return -1;
	}
      mcrypt_generic_deinit (block_engine);

      /* write the encrypted block in the fallen hash of the user's password */
      memcpy (&header[fall], &pblock, sizeof (pblock));
    }

  if (fwrite (header, 1, es->header_length, es->output) != es->header_length)
    {
      snprintf (es->error, ELEN, "error in writing header: %s",
		strerror (errno));
      return -1;
    }

  free (IV);
  free (key);

  return 0;
}
