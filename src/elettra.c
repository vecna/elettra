/*
 *    DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE.
 * TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION:
 *
 *    0. You just DO WHAT THE FUCK YOU WANT TO.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "elettra.h"

static int
elettra_example (const char *baptism)
{

  char *example =
    "\nElettra has five command: encrypt, decrypt, checkpass, help and example.\n"
    "is executed with: %s command [args]\n"
    "we want to encrypt file /tmp/ls-manpage and /tmp/ps-manpage.\n"
    "two file = two password we use \"weirdness\" and \"xYZ1shower\", the order link:\n"
    "\tls-manpage (weirdness)\n"
    "\tps-manpage (xYZ1shower)\n"
    "$ %s encrypt /dev/shm/output 15% /tmp/ls-manpage::weirdness /tmp/ps-manpage::xYZ1shower\n\n"
    "the size of our source file are:\n"
    "$ ls -l /tmp/ls-manpage /tmp/ps-manpage \n"
    "-rw-r--r-- 1 user user  7132 Jan  8 05:57 /tmp/ls-manpage\n"
    "-rw-r--r-- 1 user user 36287 Jan  8 05:57 /tmp/ps-manpage\n\n"
    "the command line specify 15%% of random padding (this percentage is optional for\n"
    "command line, is required, with \"encrypt\" directive, the output file, the sources \n"
    "file and the passwords. if passwords are not inserted via command line, are ask \n"
    "with ECHO OFF). \n"
    "before the encryption gzip compression is used, the output file is:\n\n"
    "$ ls -l /dev/shm/output \n"
    "-rw-r--r-- 1 user user 42615 Jan  8 06:13 /dev/shm/output \n\n"
    "now we had an encrypted archive, the Elettra decryption routine take a password \n"
    "and, optionally, a destination directory:\n"
    "$ %s decrypt /dev/shm/output weirdness /dev/shm/\n"
    "$ ls -l /dev/shm/\n"
    "-rw-r--r-- 1 user user  7132 Jan  8 06:32 ls-manpage\n"
    "-rw-r--r-- 1 user user 42615 Jan  8 06:13 output\n\n";

  printf (example, baptism, baptism, baptism);

  return -ELET_INVALID_ARG;
}

static int
elettra_help (const char *baptism)
{
  struct stat st;
  char *auth = "julia@winstonsmith.info", *site =
    "https://www.winstonsmith.info/julia", *randmsg;

  /* pseudo easter egg */
  stat (baptism, &st);

  switch (((unsigned int) st.st_ino % 4))
    {
    case 1:
      randmsg =
	"julia is an anonymous shared identity to produce software able to protect freedom";
      break;
    case 2:
      randmsg =
	"You should improve the quality of life, using privacy enhancing technology!";
      break;
    case 3:
      randmsg =
	"cryptography is free, improver security and doesn't give problem. for this reason, is better use when you could";
      break;
    case 0:
    default:
      randmsg = "I protect your files, in Internet you must protect yourself";
      break;
    }

  printf ("%s by %s, %s\n%s\n", baptism, auth, site, randmsg);
  printf
    ("%s encrypt outputfile [size increment]%% plainfile[::password]\n",
     baptism);
  printf ("%s decrypt cipherfile [password] [output directory]\n", baptism);
  printf ("%s checkpass password(s)\n", baptism);
  printf ("%s example (show examples of use)\n", baptism);
  printf ("- passwords, if not available, is ask with echo off\n");

  return -ELET_INVALID_ARG;
}

static int
elettra_encrypt_things (const int ac, const char **av)
{
  FILE *output;
  int i, first_file_arg, err;
  struct elettra_stream *es;
  /* for change the data of output file */
  struct timeval randdate[2];

  if (av[2][strlen(av[2]) -1] == '%')
    {
      fprintf(stderr, "padding percentage used as output file: %s\n", 
              av[2]);
      return -ELET_INVALID_ARG;
    }

  if ((output = fopen (av[2], "w+")) == NULL)
    {
      fprintf (stderr, "unable to open output file %s: %s\n",
	       av[2], strerror (errno));
      return errno;
    }
  /* output is closed because reopened later */
  fclose (output);

  if ((es = malloc (sizeof (struct elettra_stream))) == NULL)
    {
      fprintf (stderr, "unable to malloc %d bytes: %s\n",
	       sizeof (struct elettra_stream), strerror (errno));
      return errno;
    }
  memset (es, 0x00, sizeof (struct elettra_stream));

  /* init our internal structs and modules */
  if (elettra_init (es))
    {
      fprintf (stderr, "unable to init elettra: %s\n", es->error);
      return -ELET_INVALID_INIT;
    }

  /* one file or more ? check the argument in elettra_encrypt.c */
  if ((first_file_arg = get_percentage (ac, av, es)) == -1)
    {
      fprintf (stderr, "invalid percentage: %s\n", es->error);
      return -ELET_INVALID_PERCENT;
    }

  if (first_file_arg == ac)
    {
      fprintf (stderr, "Required input file\n");
      return -ELET_INVALID_PERCENT;
    }

  es->outfname = strdup (av[2]);

  /* not checked only -1 as ret, because should return different code */
  if ((err = import_password (ac, av, es, first_file_arg)) < 0)
    {
      fprintf (stderr, "import_password: %s\n", es->error);
      return err;
    }

  /* try to create an header */
  for (i = 0; i < MAX_INTERNAL_TRY; i++)
    {
      if ((es->header_length =
	   check_password_hdr (es->passlist, es->file_number)) != 0)
	break;
    }

  if (es->header_length == 0)
    {
      fprintf (stderr,
	       "unable to build a key header with your passwords, try to check them with command \"checkpass\"\n");
      return -ELET_TOOCOLLIDE;
    }

  /* acquire the file list and compress it */
  for (i = 0; i < es->file_number; i++)
    {
      if (acquire_file (es->ft[i].fname, es))
	{
	  fprintf (stderr, "unable to acquire %s: %s\n", es->ft[i].fname,
		   es->error);
	  return -ELET_INVALID_FILE;
	}
    }

  /*
   * now our files are compressed and formatted in "struct elettra_fileformat".
   */

  /*
   * alloc_internal_array defines the output file (padding for alignment, padding
   * for cover files and files)
   */
  if (alloc_internal_array (es))
    {
      fprintf (stderr, "internal operations fail: %s\n", es->error);
      return -ELET_INIT_INTERNAL;
    }
  /*
   * for each file, search for a password able to collide between min_ep and max_ep
   */
  for (i = 0; i < es->source_files; i++)
    {
      if (!search_passwords (es))
	{
	  fprintf (stderr,
		   "unable to retrive random key able to collide in our ranges (in %d tries)\n",
		   MAX_BRUTEFORCE_TRY);
	  fprintf (stderr,
		   "we suggest to lower the number of files or use less difference between size of files\n");
	  fprintf (stderr, "... or just retry :)\n");
	  return -ELET_FAIL_COLLISION;
	}
    }

  /* open the file, create the header, write the header, and write encrypted data with elettra_final_write */
  if ((es->output = fopen (es->outfname, "w+")) == NULL)
    {
      fprintf (stderr, "unable to open file %s: %s\n", es->outfname,
	       strerror (errno));
      return -ELET_FILE_WRITE;
    }

  if (elettra_header_write (es))
    {
      fprintf (stderr, "error in writing header in output file: %s\n",
	       es->error);
      return -ELET_FILE_WRITE;
    }

  /* now, with the password, crypt and write the data! */
  if (elettra_final_write (es))
    {
      fprintf (stderr, "error in writing output file: %s\n", es->error);
      return -ELET_FILE_WRITE;
    }

  fclose (es->output);

#define RANDOM_CTIME /* comment this line for keep a correct ctime */
#ifdef RANDOM_CTIME
  /* random range of file data change */
#define WEEK52	( 60 * 60 * 24 * 7 * 52 )
#define DAY30 	( 60 * 60 * 24 * 30 )
#define DAY1 	( 60 * 60 * 24 )
#define HOUR1	( 60 * 60 )

  gettimeofday(&randdate[0], NULL);
  randdate[0].tv_sec -= rand() % DAY30;
  randdate[0].tv_sec += rand() % DAY30;

  gettimeofday(&randdate[1], NULL);
  randdate[1].tv_sec -= rand() % DAY30;
  randdate[1].tv_sec += rand() % DAY30;

  utimes(es->outfname, (const struct timeval *)&randdate); 
#endif /* RANDOM_CTIME */

  return 0;
}

static int
elettra_seek_things (int ac, const char **av)
{
  char *fname, *directory, *password;
  unsigned char extracted_key[KEYLEN];
  FILE *input;
  int header_length;
  unsigned int entry_point;
  struct stat st;

  if ((input = fopen (av[2], "r")) == NULL)
    {
      fprintf (stderr, "unable to open %s: %s\n", av[2], strerror (errno));
      return -ELET_READ_CRYPFILE;
    }

  directory = NULL;

  /* elettra decrypt file [pass] [dir] */
  if (stat (av[ac - 1], &st) == 0 && S_ISDIR (st.st_mode))
    {
      directory = (char *) av[ac - 1];

      if (ac == 5)
	password = strdup (av[3]);
      else
	{
	  printf ("decrypt [%s] ", av[2]);
	  fflush (stdout);
	  password = getpass ("password: ");
	}
    }
  else
    {
      /* elettra decrypt file [pass] */
      if (ac == 4)
	password = strdup (av[3]);
      else
	{
	  printf ("decrypt [%s] ", av[2]);
	  fflush (stdout);
	  password = getpass ("password: ");
	}
    }

  if ((header_length = extract_key (extracted_key, input, password)) == -1)
    {
      fprintf (stderr,
	       "invalid password or invalid file, I didn't find any valid key header\n");
      return -ELET_INVALID_PASS;
    }

  stat (av[2], &st);
  entry_point = get_hash_ep (extracted_key, KEYLEN, st.st_size);

  /* 
   * in encryption time, password entry point is '%' module with header_length, random
   * internl_key of 12 byte = KEYLEN is '%' module with es->finalsize, that contains
   * header_length. but min_ep and max_ep and last_used_offset are not involved with
   * header length. here we receive the entry point derived from extracted_key, but 
   * the encypted+random data is after the header, that is included for module reason but
   * must me excluded from the fseek() called in decrypt_entry_p. ok ? Y/N
   */
  entry_point += header_length;

  if (decrypt_entry_p (entry_point, input, extracted_key, directory, &fname))
    {
      fprintf (stderr,
	       "unable to decrypt correctly the file %s (%u byte)\n",
	       av[2], (unsigned int) st.st_size);
      return -ELET_BAD_EP;
    }
  if (elettra_ungzip (fname))
    return -ELET_BAD_DECOMPR;

  return 0;
}

static int
elettra_checkpass (int ac, const char **av)
{
  char *p, **passlist = NULL;
  int ret, i, len = 0;

  if (ac > 2)
    {
      for (i = 2; i < ac; i++)
	{
	  passlist = realloc (passlist, sizeof (char *) * (i - 1));

	  if (strlen (av[i]) < MINLENPASS)
	    {
	      fprintf (stderr, "Invalid password, required %d bytes\n",
		       MINLENPASS);
	      return -ELET_PASSSHORT;

	    }
	  passlist[len] = strdup (av[i]);
	  len++;
	}
    }
  else
    {
      printf
	("checkpass getting passwords from terminal, empty password for finish\n");
      i = 0;

      while (1)
	{
	  p = getpass ("password: ");
	  len = strlen (p);

	  if (!len)
	    break;

	  if (len < MINLENPASS)
	    {
	      fprintf (stderr, "Invalid password. required %d bytes\n",
		       MINLENPASS);
	      continue;
	    }

	  i++;
	  passlist = realloc (passlist, sizeof (char *) * i);
	  passlist[i - 1] = strdup (p);
	}

      /* number of passwords */
      len = i;
    }

  /* implemented in elettra_check.c */
  ret = check_password_hdr (passlist, len);

  if (!ret)
    {
      fprintf (stderr,
	       "your passwords CANNOT cooperate, try other sequence and avoid password duplication\n");
      return -ELET_BAD_PASSWORD_LIST;
    }

  fprintf (stderr,
	   "password(s) combinations work ok, atleast with password block of %d bytes\n",
	   ret);
  return 0;
}

int
main (int argc, const char **argv)
{
  int ret;
  /*
   * in this function the command line options are checked, and passed
   * to elettra_encrypt.c for encryption and elettra_seek.c
   * for decryption.
   */
  if (argc == 1 || !strcmp (argv[1], "-h") || strstr (argv[1], "help"))
    return elettra_help (argv[0]);

  if (!strcmp (argv[1], "encrypt") && argc >= 4)
    {
      ret = elettra_encrypt_things (argc, argv);

      if (ret)
	unlink (argv[3]);

      return ret;
    }
  if (!strcmp (argv[1], "decrypt") && argc >= 3)
    return elettra_seek_things (argc, argv);

  /* core functions implemented in elettra_check.c */
  if (!strcmp (argv[1], "checkpass"))
    return elettra_checkpass (argc, argv);

  /* implemented here */
  if (!strcmp (argv[1], "example"))
    return elettra_example (argv[0]);

  return elettra_help (argv[0]);
}
