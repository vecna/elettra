#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>

#include <mhash.h>
#include <mcrypt.h>

#include "elettra.h"

/*
 * this is the partial header read from elettra file, to
 * decrypt the exact length of the file
 */
struct elettra_partial_hdr
{
  unsigned int checksum;
  int compr_len;
};

int
decrypt_entry_p (unsigned int entry_p, FILE * input, unsigned char *extracted_key,
		 char *directory, char **fname)
{
  struct elettra_partial_hdr *eph;
  unsigned char *bulk, *key, *IV;
  unsigned int keysum;
  int index, fname_len, compr_len, nbyte, blen, ivsize, keysize;
  MCRYPT decrypt_engine;
  FILE *gzout;

  decrypt_engine = mcrypt_module_open ("rijndael-128", NULL, "cbc", NULL);

  ivsize = mcrypt_enc_get_iv_size (decrypt_engine);
  keysize = mcrypt_enc_get_key_size (decrypt_engine);
  IV = malloc (ivsize);
  key = malloc (keysize);

  fseek (input, entry_p, SEEK_SET);

  /* the first read segment is the minimum size of decryptable block */
  blen = mcrypt_enc_get_block_size (decrypt_engine);
  bulk = malloc (blen);

  nbyte = fread (bulk, 1, blen, input);

  set_password_hash (key, keysize, IV, ivsize, extracted_key, KEYLEN);
  mcrypt_generic_init (decrypt_engine, key, keysize, IV);

  /* this function decrypts the block(s) */
  mdecrypt_generic (decrypt_engine, bulk, blen);

  /* acquire length information and check if extracted_key is valid */
  eph = (struct elettra_partial_hdr *) bulk;
  keysum = elettra_key_checksum (key, keysize);
  if (keysum != eph->checksum)
    {
      fprintf (stderr,
	       "extracted key appears invalid, checksum %08X don't match %08X\n",
	       keysum, eph->checksum);
      return -1;
    }
  compr_len = eph->compr_len;

  /* prepare the buffer to decrypt full file + fname + partial hdr */
  blen = (compr_len + MAXPATHLEN + blen);
  if ((bulk = realloc (bulk, blen)) == NULL)
    {
      fprintf (stderr, "malloc of %d byte: %s\n", blen, strerror (errno));
      return -1;
    }
  index = mcrypt_enc_get_block_size (decrypt_engine);
  nbyte = fread (&bulk[index], 1, (blen - index), input);
  mdecrypt_generic (decrypt_engine, &bulk[index], nbyte);

  /* the file name and the file name length at the end of the block */
  index = compr_len + sizeof (struct elettra_partial_hdr);
  memcpy (&fname_len, &bulk[index], sizeof (int));

  if ((*fname = malloc (fname_len + 1)) == NULL)
    {
      fprintf (stderr, "unable to alloc %d bytes: %s\n",
	       fname_len, strerror (errno));
      return -1;
    }
  memset (*fname, 0x00, fname_len + 1);
  memcpy (*fname, &bulk[index + sizeof (int)], fname_len);

#if 0
  printf ("decrypted file [%s] compressed length %d\n", *fname, compr_len);
#endif

  fclose (input);
  mcrypt_generic_deinit (decrypt_engine);

  if (directory && chdir (directory) == -1)
    {
      fprintf (stderr, "unable to change directory to %s: %s\n",
	       directory, strerror (errno));
      return -1;
    }
  if ((gzout = fopen (*fname, "w+")) == NULL)
    {
      fprintf (stderr, "unable to create file: %s: %s\n",
	       *fname, strerror (errno));
      return -1;
    }
  fwrite (&bulk[sizeof (struct elettra_partial_hdr)], 1, compr_len, gzout);
  fclose (gzout);
  free (bulk);

  return 0;
}
