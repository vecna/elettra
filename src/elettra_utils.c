#include <mhash.h>
#include "elettra.h"

static char *hashblock;

static void init_hashblock(void)
{
#define VARIOUS_POURPOSE_HASH_SIZE	256
    if (hashblock == NULL) {
	hashblock = malloc(VARIOUS_POURPOSE_HASH_SIZE);
    }
}

/*
 * compute_hash is used to compute hashes of password and use them for IV and
 * key
 */
static int compute_hash(void *data, int len, hashid hash_type)
{
    MHASH hash_engine;

    init_hashblock();

    memset(hashblock, 0x00, VARIOUS_POURPOSE_HASH_SIZE);
    hash_engine = mhash_init(hash_type);
    mhash(hash_engine, data, len);
    mhash_deinit(hash_engine, hashblock);

    return mhash_get_block_size(hash_type);
}

/* transform password string in hash for key and copy the IV */
void
set_password_hash(unsigned char *key, int keysize, unsigned char *IV,
		  int ivsize, const unsigned char *pass, int passlen)
{
    unsigned char base_str[KEYLEN];
    int i, k, length;

    /* 
     * set_password_hash pad with 'B' and get_hash_ep pad with 'A' 
     * for give less correlation possibility
     */
    if (passlen != KEYLEN) {
	memset(base_str, 'B', KEYLEN);
	if (passlen > KEYLEN)
	    passlen = KEYLEN;
    }

    /* and set up base_str in both case */
    memcpy(base_str, pass, passlen);

    /* 
     * fixed value for encryption blocks:
     * sha1 output hash 20 byte, 
     * md5 output hash 16, 
     * the key is 32 byte and the IV 16 (fixed value)
     */
    memset(key, 0x00, keysize);

    length =compute_hash(base_str, KEYLEN, MHASH_SHA1);
    for(k = 0, i = 0; i < length; i++, k++)
	key[i] = hashblock[k];

    /* 
     * I don't want that the key depends from the SAME 
     * string hashed with different algorithm, for this 
     * reason some bytes are XORed with preivous sha1-hash
     * like a feedback
     */
    base_str[2] ^= hashblock[2];
    base_str[3] ^= hashblock[3];
    base_str[5] ^= hashblock[5];

    compute_hash(base_str, KEYLEN, MHASH_MD5);
    for(k =0, i = length; i < keysize; i++, k++)
        key[i] = hashblock[k];

#define INITIALIZATION_VECTOR	"LK+DOE+EEN+GOK++"
    memcpy(IV, INITIALIZATION_VECTOR, ivsize);
}

unsigned int
get_hash_ep(const unsigned char *pass, int passlen, int module)
{
#define PASSMAXLEN	128
    char expand[PASSMAXLEN];
    unsigned int ret = 0;

    /* get_hash_ep pad with 'A' and set_password_hash pad with 'B' */
    memset(expand, 'A', PASSMAXLEN);

    /* truncate buffer larger than 128 */
    if(passlen > PASSMAXLEN)
	passlen = PASSMAXLEN;

    /* 
     * passlen shoud be KEYLEN at encryption time or strlen(pass) in header time,
     * the expand string is initialized with 'A'
     */
    memcpy(expand, pass, passlen);

    compute_hash(expand, PASSMAXLEN, MHASH_SHA256);

    /* only first 8 bytes are used */
    ret =
	*((unsigned int *) hashblock) ^ *((unsigned int *)
					  &hashblock[sizeof(int)]);

    return (ret % module);
}

/* get random for random init */
void fill_me_with_entropy(unsigned char *dest, int len)
{
#define INITLEN	16
    int i, blob[INITLEN], carry;

    for (i = 0; i < INITLEN; i++)
	blob[i] = rand();

    compute_hash(blob, sizeof(int) * INITLEN, MHASH_SHA256);

    for (i = 0; i < len; i++) {
	carry = (i + 1) % mhash_get_block_size(MHASH_SHA256);

	dest[i] = hashblock[carry];

	/* when hashblock has been used, refreh our entropy pool */
	if (!carry) {
	    blob[0] = rand();
	    compute_hash(blob, sizeof(int) * INITLEN, MHASH_SHA256);
	}
    }
}

unsigned int
elettra_key_checksum(unsigned char *key, int keysize)
{
    unsigned int ret = 1;
    int i;

    /*
     * to check if the password is correct I'm using a checksum 
     * of the key
     */
    for (i = 0; i < (keysize - 1); i++) 
    {
	ret ^= (unsigned short)key[i] * (unsigned short)key[i + 1];
    }

    return ret;
}
