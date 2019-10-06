/*
 * This file is governed by Licenses which are listed in
 * the LICENSE file, which shall be included in all copies
 * and redistributions of this project.
 */

#include "openssh-key.h"

/* opaque EC_KEY + ECDSA NIDs to make it compile for now .. */
typedef struct EC_KEY EC_KEY;
enum ecdsa_nids { NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1 };

/* +-------------------+ */
/* | structs and types | */
/* +-------------------+ */

/* openssh key struct */
struct opensshkey {
    int	 type;
	/* ecdsa nist curves */
	int	    ecdsa_nid;
	EC_KEY *ecdsa_key;
    /* ed25519 curve */
	unsigned char *ed25519_sk;
	unsigned char *ed25519_pk;
};

/* supported key types */
static const struct {
	const char *name;
	const char *shortname;
	int type;
    int nid;
    int iscert;
} supported_keytypes[] = {
/*    name                                          shortname       type                ecdsa_nid             cert */
	{ "ssh-ed25519",                                "ED25519",      KEY_ED25519,        -1,                     0 },
	{ "ssh-ed25519-cert-v01@openssh.com",           "ED25519-CERT", KEY_ED25519_CERT,   -1,                     1 },
    { "ecdsa-sha2-nistp256",                        "ECDSA",        KEY_ECDSA,          NID_X9_62_prime256v1,   0 },
	{ "ecdsa-sha2-nistp256-cert-v01@openssh.com",   "ECDSA-CERT",   KEY_ECDSA_CERT,     NID_X9_62_prime256v1,   1 },
	{ "ecdsa-sha2-nistp384",                        "ECDSA",        KEY_ECDSA,          NID_secp384r1,          0 },
	{ "ecdsa-sha2-nistp384-cert-v01@openssh.com",   "ECDSA-CERT",   KEY_ECDSA_CERT,     NID_secp384r1,          1 },
	{ "ecdsa-sha2-nistp521",                        "ECDSA",        KEY_ECDSA,          NID_secp521r1,          0 },
	{ "ecdsa-sha2-nistp521-cert-v01@openssh.com",   "ECDSA-CERT",   KEY_ECDSA_CERT,     NID_secp521r1,          1 },
    { "unknown",                                    "UNKNOWN",      KEY_UNKNOWN,        -1,                     0 },
};
#define n_supported_keytypes sizeof supported_keytypes / sizeof *supported_keytypes


/* +--------------------------------+ */
/* | newly allocate or cleanly free | */
/* +--------------------------------+ */

/* allocate new*/
struct opensshkey *newopensshkey (int type)
{
    struct opensshkey *newkey;

    if (type > KEY_UNKNOWN)
        return NULL;

    if ((newkey = zalloc(sizeof *newkey)) == NULL)
        return NULL;
    
    newkey->type = type;
    newkey->ecdsa_key = NULL;
    newkey->ecdsa_nid = -1;
    newkey->ed25519_sk = NULL;
    newkey->ed25519_pk = NULL;

    return newkey;
}

/* free with explicit zeroing */
void freeopensshkey (struct opensshkey *key)
{
    if (key == NULL)
        return;

    switch (key->type) {

        case KEY_ED25519:
        case KEY_ED25519_CERT:
            /* memzero() pointers and free */
            nullpointer(key->ed25519_pk, ED25519_PUBLICKEY_SIZE);
            nullpointer(key->ed25519_sk, ED25519_SECRETKEY_SIZE);
            break;

        case KEY_ECDSA:
        case KEY_ECDSA_CERT:
        /* requires openssl or libressl ..
            if (key->ecdsa_key != NULL)
                EC_KEY_free(key->ecdsa_key);
            key->ecdsa_key = NULL;
            break; */
        
        case KEY_UNKNOWN:
        default:
            break;

    }

    /* free struct itself */
    nullpointer(key, sizeof *key);
    return;
}


/* +--------------------+ */
/* | keytype operations | */
/* +--------------------+ */

/* detect key type from given string */
int opensshkey_detect_type (const unsigned char *name)
{
    for (int i = 0; i < n_supported_keytypes; i++) {
        /* the supported keytype has invalid names */
        if (supported_keytypes[i].name == NULL || supported_keytypes[i].shortname == NULL)
            continue;
        /* match long name */
        if (strcmp(name, supported_keytypes[i].name) == 0 ||
        /* or match short name */
            strcasecmp(name, supported_keytypes[i].shortname) == 0)
                return supported_keytypes[i].type;
    }
    return KEY_UNKNOWN;
}

int opensshkey_get_type (const struct opensshkey *key)
{
    if (key == NULL)
        return KEY_UNSPECIFIED;
    
    return key->type;
}

const unsigned char *opensshkey_get_typename (const struct opensshkey *key)
{
    if (key == NULL)
        return NULL;

    for (int i = 0; i < n_supported_keytypes; i++) {
        /* the supported keytype has invalid names */
        if (supported_keytypes[i].name == NULL || supported_keytypes[i].shortname == NULL)
            continue;
        /* match keytype */
        if (key->type == supported_keytypes[i].type &&
        /* and match nid */
            key->ecdsa_nid == supported_keytypes[i].nid)
                
                return supported_keytypes[i].name;
    }
    return NULL;
}

/* +----------------------------+ */
/* | operations on key material | */
/* +----------------------------+ */

/* set pk and sk on ed25519 key */
int opensshkey_set_ed25519_keys (struct opensshkey *key, unsigned char *pk, unsigned char *sk)
{
    if (key == NULL)
        return ERR_NULLPTR;

    /* key must be ed25519 key */
    if ( !(key->type == KEY_ED25519 || key->type == KEY_ED25519_CERT) )
        return OPENSSH_KEY_INCOMPATIBLE;

    /* set new public key */
    if (pk != NULL)
        key->ed25519_pk = pk;

    /* set new privatekey */
    if (sk != NULL)
        key->ed25519_sk = sk;
    
    return SUCCESS;
}

/* return public and private part of elliptic curve keys */
int opensshkey_save_to_tinyssh (const struct opensshkey *key, const unsigned char *dir)
{
    if (key == NULL)
        return ERR_NULLPTR;

    int e = FAILURE;

    /* pointers to data to be written */
    unsigned char *seckey = NULL, *pubkey = NULL;
    size_t seckey_len = 0, pubkey_len = 0;

    /* strings to construct the filenames in */
    unsigned char pubkey_file[1024 + 64] = "", seckey_file[1024 + 64] = "";
    strncat(pubkey_file, dir, 1023);
    strncat(seckey_file, dir, 1023);
    /* if last character is not a slash, append it */
    if (strncmp(seckey_file + strlen(seckey_file) - 1, "/", 1) != 0) {
        strncat(pubkey_file, "/", 2);
        strncat(seckey_file, "/", 2);
    }

    /* decide by key type */
    switch (key->type) {

        case KEY_ED25519:
        case KEY_ED25519_CERT:

            /* we need a private key but could use
               the embedded public key there. use public
               key anyway, as it is easier pointer math */
            if (key->ed25519_sk == NULL || key->ed25519_pk == NULL)
                cleanreturn(ERR_NULLPTR);
            
            /* set pointers and lengths */
            seckey = key->ed25519_sk;
            seckey_len = ED25519_SECRETKEY_SIZE;
            pubkey = key->ed25519_pk;
            pubkey_len = ED25519_PUBLICKEY_SIZE;

            /* construct the filenames */
            strncat(pubkey_file, ED25519_PUBLIC_TINYSSH_NAME, sizeof ED25519_PUBLIC_TINYSSH_NAME);
            strncat(seckey_file, ED25519_SECRET_TINYSSH_NAME, sizeof ED25519_SECRET_TINYSSH_NAME);

            break;
        
        case KEY_ECDSA:
        case KEY_ECDSA_CERT:
            /* not supported yet, requires ssl library */
        
        case KEY_UNKNOWN:
        case KEY_UNSPECIFIED:
        default:
            return OPENSSH_KEY_UNKNOWN_KEYTYPE;
    }

    /* write keys */
    if (seckey != NULL && pubkey != NULL) {
        /* secret key */
        printf("writing seckey to: %s ...\n", seckey_file);
        if ((e = savestring(seckey_file, seckey, seckey_len)) != SUCCESS)
            cleanreturn(e);
        /* public key */
        printf("writing pubkey to: %s ...\n", pubkey_file);
        if ((e = savestring(pubkey_file, pubkey, pubkey_len)) != SUCCESS)
            cleanreturn(e);
    }
    
    /* housekeeping .. */
    cleanup:
        seckey = NULL;
        pubkey = NULL;
    
    return e;
}

/* +-----------+ */
/* | debugging | */
/* +-----------+ */

void opensshkey_dump (const struct opensshkey *key)
{
    
    if (key == NULL) {
        printf("Passed key pointer is NULL!\n");
        return;
    }

    printf("Dumping opensshkey ...\n");

    switch (key->type) {
        case KEY_ECDSA:
        case KEY_ECDSA_CERT:
            printf("Keytype is: ECDSA (unsupported)\n");
            break;
        case KEY_ED25519:
        case KEY_ED25519_CERT:
            printf("Keytype is: ed25519\n");
            debugbuf("ed25519 public key", key->ed25519_pk, ED25519_PUBLICKEY_SIZE);
            debugbuf("ed25519 secret key", key->ed25519_sk, ED25519_SECRETKEY_SIZE);
            break;
        case KEY_UNKNOWN:
        default:
            printf("Keytype is UNKNOWN!\n");
            break;
    }

}