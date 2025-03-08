

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ep11.h>


#define ARRAY_ELEMS(arr)  (sizeof(arr) / sizeof((arr)[0]))
CK_BBOOL ltrue = CK_TRUE;


/*----------------------------------------------------------------------------*/
/* generate_rsa_key                                                           */
/*   function to generate an RSA public/private key token                     */
/* Inputs:                                                                    */
/*   place to store RSA key                                                   */
/* Outputs:                                                                   */
/*   RSA public/private key token and length                                  */
/*   return code (success/failure)                                            */
/*----------------------------------------------------------------------------*/
// int
// generate_rsa_key( long          * pRSAkeySize,
//                   long          * pRSAPrivateKeyTokenLength,
//                   unsigned char * pRSAPrivateKeyToken )
// {
CK_RV generate_rsa_keypair(target_t *target, unsigned long mod_bits,
                        uint8_t *prv, size_t *prv_len,
                        uint8_t *pub, size_t *pub_len)
{
    CK_RV rv;
    CK_MECHANISM mech;
    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_RSA_X9_31_KEY_PAIR_GEN;

	CK_ATTRIBUTE puba[] = {
		{ CKA_WRAP,          &ltrue,   sizeof(ltrue)     },
		{ CKA_MODULUS_BITS,  &mod_bits,
		                               sizeof(mod_bits) },
		{ CKA_MODIFIABLE,    &ltrue,   sizeof(ltrue)     },
		//{ CKA_PUBLIC_EXPONENT,
		//                     (CK_VOID_PTR) expn,
		//                               elen              },
	} ;
	CK_ATTRIBUTE prva[] = {
		{ CKA_DECRYPT,  &ltrue, sizeof(ltrue) },
		{ CKA_SIGN,     &ltrue, sizeof(ltrue) },
		{ CKA_UNWRAP,   &ltrue, sizeof(ltrue) },
	} ;
    
    printf("INFO: Generating RSA key pair ...\n");
    rv = m_GenerateKeyPair(&mech,
                            puba, ARRAY_ELEMS(puba),
	                       prva, ARRAY_ELEMS(prva),
                           NULL, 0,
	                       prv, prv_len,
                           pub, pub_len,
	                       *target);
    if (rv != CKR_OK)
    {
    	printf("ERROR: m_GenerateKey...FAILED! rv = 0x%lx\n", rv);
    }
    return rv;
}



	// CKM_SHA384_RSA_PKCS,
	// CKM_SHA256_RSA_PKCS,
	// CKM_SHA1_RSA_PKCS,
	// CKM_SHA1_RSA_X9_31,
	// CKM_SHA512_RSA_PKCS,


CK_RV rsa_sign(target_t *target,
                        uint8_t *prv, size_t prv_len,
                        uint8_t *data, size_t data_len,
                        uint8_t *sig, size_t *sig_len)
{
    CK_RV rv;
    CK_MECHANISM mech;
    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    printf("INFO: Generating RSA signature ...\n");
    rv = m_SignSingle(prv, prv_len, &mech,
                        data, data_len,
	                  sig, sig_len, *target);
    if (rv != CKR_OK)
    {
    	printf("ERROR: m_SignSingle...FAILED! rv = 0x%lx\n", rv);
    }
    return rv;
}


CK_RV rsa_verify(target_t *target,
                        uint8_t *key, size_t key_len,
                        uint8_t *data, size_t data_len,
                        uint8_t *sig, size_t sig_len)
{
    CK_RV rv;
    CK_MECHANISM mech;
    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    printf("INFO: Verifying RSA signature ...\n");
    rv = m_VerifySingle(key, key_len, &mech, data, data_len,
		                    sig, sig_len, *target);
    if (rv != CKR_OK)
    {
    	printf("ERROR: m_VerifySingle...FAILED! rv = 0x%lx\n", rv);
    }
    return rv;
}


void print_hex(const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", key[i]);  // Print each byte as a two-character hex value
      /*  if (i < key_len - 1) {
            printf(" ");  // Add space between bytes (optional)
        }*/
    }
    printf("\n");
}





CK_RV generate_aes_key(target_t *target, size_t key_size, uint8_t *key, size_t *key_len)
{
    CK_RV rv;
    CK_MECHANISM mech;
    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_KEY_GEN;
    unsigned char   csum[ 64 ];
    size_t cslen  = sizeof(csum);
    CK_ATTRIBUTE_TYPE ksize = key_size/8;
    CK_ATTRIBUTE kek_attrs[] = {
        { CKA_VALUE_LEN, &ksize, sizeof(ksize) },
        { CKA_ENCRYPT,   &ltrue, sizeof(ltrue) },
        { CKA_UNWRAP,    &ltrue, sizeof(ltrue) },
    };
    
    printf("INFO: Generating AES key ...\n");
    rv = m_GenerateKey(&mech, kek_attrs, ARRAY_ELEMS(kek_attrs), NULL, ~0,
	                   key, key_len, csum, &cslen, *target);
    if (rv != CKR_OK)
    {
    	printf("ERROR: m_GenerateKey...FAILED!\n");
    }

    print_hex(key,*key_len);   

    return rv;
}





// Helper function for EP11 lib shutdown
static int lib_shutdown(int rc)
{
    printf("Shutting down EP11 library ...");

	if (m_shutdown() != XCP_OK) {
        printf("Error shutting down EP11 library");
		return EXIT_FAILURE;
	}
	return rc;
}


// Entry point and boiler plate code to setup EP11
int main(int argc, char** argv)
{
    printf("EP11 RSA Sign starts ...\n");


    int32_t module_nr = 3;  // TODO: Parse an argument to indicate which module
    int32_t domain_nr = 19;  // TODO: Parse an argument to indicate which domain

    int rc;
    CK_RV rv;
    target_t target = XCP_TGT_INIT;
    struct XCP_Module module = {.version = XCP_MOD_VERSION};
    

    printf("Initializing EP11 library ...\n");
	rc = m_init();
	if (rc != XCP_OK) {
        printf("Error initializing EP11 library (rc=%d)\n", rc);
		return EXIT_FAILURE;
	}


    printf("Creating target ...\n");
    module.module_nr = module_nr;
	XCPTGTMASK_SET_DOM(module.domainmask, domain_nr);
	module.flags |= XCP_MFL_MODULE | XCP_MFL_PROBE;
	rc = m_add_module(&module, &target);

        printf("%02x\n", rc); // No space after each value
	if (rc != XCP_OK) {
                printf("Error creating target (rc=%d)\n", rc);
		return lib_shutdown(EXIT_FAILURE);
	}

    // Module ready
    size_t key_size = 256;
    uint8_t key[9000];
    size_t key_len = sizeof(key);
    rv = generate_aes_key(&target, key_size, key, &key_len);
	if (rv != CKR_OK) {
        printf("Error creating target (rc=%d)\n", rc);
		return lib_shutdown(EXIT_FAILURE);
	}


    // Generate RSA Key Pair
    unsigned long mod_bits = 2048;
    uint8_t prv[9000];
    size_t prv_len = sizeof(key);
    uint8_t pub[9000];
    size_t pub_len = sizeof(key);
    rv = generate_rsa_keypair(&target, mod_bits,
                        prv, &prv_len,
                        pub, &pub_len);
	if (rv != CKR_OK) {
        printf("Error creating RSA keypair (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}

    // Sign
    uint8_t data[9000];
    size_t data_len = sizeof(data);
    uint8_t sig[9000];
    size_t sig_len = sizeof(sig);
    rv = rsa_sign(&target,
                        prv, prv_len,
                        data, data_len,
                        sig, &sig_len);
	if (rv != CKR_OK) {
        printf("Error creating RSA signature (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}



    // Verify
    rv = rsa_verify(&target,
                        pub, pub_len,
                        data, data_len,
                        sig, sig_len);
	if (rv != CKR_OK) {
        printf("Error verifying RSA signature (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}






    printf("EP11 RSA Sign ends ...\n");
    return EXIT_SUCCESS;
}

