#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mcrypt.h>

/*
 * the encrypted files are stored in the output file with this format
 * and in this order. 
 */
struct elettra_fileformat
{
  unsigned int key_sum;	/* checksum of the key */
  unsigned char *compr_data;
  int compr_len;
  int fname_len;
  char *fname;
};

/*
 * struct for track password - offset
 */
struct elettra_po
{
#define KEYLEN	12
  unsigned char *internal_key;
  int entry_point;
  int min_ep;
  int max_ep;
  int post_padding;
};

/* max try for searching keys */
#define MAX_BRUTEFORCE_TRY	10000
#define MAX_INTERNAL_TRY	12

/*
 * struct for password block
 */
struct password_block
{
  unsigned char internal_key[KEYLEN];
  unsigned int checksum;
};

/* struct for track password - file */
#define MINLENPASS		6
struct filetrack
{
  char *fname;
  char *password;
  struct stat st;
};
/*
 * internal state of elettra
 */
struct elettra_stream
{
#define DEFAULT_PERCENT_PAYLOAD	27
  int percent_payload;

#define ELEN	256
  char error[ELEN];
  char *outfname;

  MCRYPT crypto_engine;
  int ivsize, keysize;
  unsigned char *IV, *key;

  int source_files;
  struct elettra_fileformat *comprf;

  int finalsize;
  struct elettra_po *epo;

  int header_length;

  char **passlist;
  int file_number;
  struct filetrack *ft;

  FILE *output;
};


#define AVAILABLE_INITBSIZE	12
#define TRY_LOOK_AT_KEYBLOCK	80	/* used when is looking for the key in the init block */
#define STARTBLOCKSIZE 512
#define STEPBLOCKSIZE  256
/* when you should try more than 12 ? */
#define WHEN_RANDOM_IS_HOPELESS	10

/*
 * functions in elettra_encrypt.c
 */
int elettra_init (struct elettra_stream *);
int get_percentage (int, const char **, struct elettra_stream *);
int acquire_file (const char *, struct elettra_stream *);
int get_password_list (const char *, struct elettra_stream *);
int alloc_internal_array (struct elettra_stream *);
int search_passwords (struct elettra_stream *);
int elettra_final_write (struct elettra_stream *);

/*
 * functions in elettra_seek.c
 */
int decrypt_entry_p (unsigned int, FILE *, unsigned char *, char *, char **);

/*
 * functions in elettra_utils.c
 */
unsigned int elettra_key_checksum (unsigned char *, int);
unsigned int get_hash_ep (const unsigned char *, int, int);
void set_password_hash (unsigned char *, int, unsigned char *, int,
			const unsigned char *, int);
void fill_me_with_entropy (unsigned char *, int);

/*
 * functions in elettra_zlib.c
 */
unsigned char *elettra_gzip (FILE *, int *, struct elettra_stream *);
int elettra_ungzip (char *);

/*
 * functions in elettra_check.c
 */
int check_password_hdr (char **, int);
int extract_key (unsigned char *, FILE *, char *);
int import_password (int, const char **, struct elettra_stream *, int);
int elettra_header_write (struct elettra_stream *);

/*
 * ERROR CODE
 */
#define ELET_INVALID_ARG	1	/* Invalid command line arg */
#define ELET_INVALID_INIT	2	/* Invalid initialization */
#define ELET_INVALID_PERCENT	5	/* Invalid percentage */
#define ELET_INVALID_FILE	6	/* Unable to open file in reading */
#define ELET_INIT_INTERNAL	7	/* Unable to init internal
					 * mcrypt/mhash */
#define ELET_FAIL_COLLISION	8	/* fail collide password in entry
					 * point */
#define ELET_FILE_WRITE		9	/* Unable to write archive */
#define ELET_READ_CRYPFILE	10	/* unable to read encrypted file */
#define ELET_BAD_EP		11	/* bad entry point found */
#define ELET_BAD_DECOMPR	12	/* fail in decompression */
#define ELET_BAD_PASSWORD_LIST	13	/* bad password list for init block */
#define ELET_READ_HEADER	14	/* may be useless with ELET_READ_CRYPFILE ? */
#define ELET_INVALID_PASS	15	/* invalid password unable to open key header */
#define ELET_INVALID_PASSINP	16	/* unable to import password from cmd line/terminal */
#define ELET_TOOCOLLIDE		17	/* unable to find an header without collision */
#define ELET_PASSSHORT		18	/* password is too short */
