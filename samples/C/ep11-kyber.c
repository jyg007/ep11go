
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ep11.h>


#define ARRAY_ELEMS(arr)  (sizeof(arr) / sizeof((arr)[0]))
CK_BBOOL ltrue = CK_TRUE;
CK_BBOOL lfalse = CK_FALSE;



CK_RV generate_kyber_keypair(target_t *target,
                        uint8_t *prv, size_t *prv_len,
                        uint8_t *pub, size_t *pub_len)
{
    CK_RV rv = CKR_OK;
    CK_MECHANISM mech;
	CK_ULONG compl = 1;
    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_IBM_KYBER;
	const char *loid = XCP_PQC_KYBER_R2_1024;
	size_t loid_len = XCP_PQC_KYBER_R2_1024_BYTES;

	CK_ATTRIBUTE puba[] = {
			// keep at 0
		{ CKA_IBM_PQC_PARAMS,      (CK_VOID_PTR) loid, loid_len      },
		{ CKA_IBM_STD_COMPLIANCE1, &compl,             sizeof(compl) },
		{ CKA_WRAP,                &ltrue,             sizeof(ltrue) },
		{ CKA_DERIVE,              &ltrue,             sizeof(ltrue) },
		{ CKA_ENCRYPT,             &ltrue,             sizeof(ltrue) },
	} ;
	CK_ATTRIBUTE prva[] = {
		{ CKA_UNWRAP,              &ltrue,             sizeof(ltrue) },
		{ CKA_IBM_STD_COMPLIANCE1, &compl,             sizeof(compl) },
		{ CKA_DERIVE,              &ltrue,             sizeof(ltrue) },
		{ CKA_DECRYPT,             &ltrue,             sizeof(ltrue) },
	} ;



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


CK_RV kyber_encapsulate(target_t *target, const unsigned char *pk,   size_t pklen,
								unsigned char *wrp, size_t *wrplen,
								unsigned char *sspk, size_t *sspklen
								)
{
    CK_RV rv = CKR_OK;
    CK_MECHANISM mech = { .mechanism = CKM_IBM_KYBER };
	struct XCP_KYBER_KEM_PARAMS kem_prm = { 0 };

	CK_ULONG dvktype = CKK_AES;
	CK_ULONG dvksize = 32;
	CK_ULONG kdftype = CKD_NULL;
	CK_ATTRIBUTE kyba[] = {
		{ CKA_KEY_TYPE,    (CK_VOID_PTR) &dvktype, sizeof(dvktype) },
		{ CKA_VALUE_LEN,   (CK_VOID_PTR) &dvksize, sizeof(dvksize) },
		{ CKA_EXTRACTABLE, (CK_VOID_PTR) &ltrue,   sizeof(lfalse)  },
	};

	kem_prm.kdf             = kdftype;
	kem_prm.mode            = CK_IBM_KEM_ENCAPSULATE;
	kem_prm.version         = XCP_KYBER_KEM_VERSION;
	kem_prm.pSharedData     = NULL;
	kem_prm.ulSharedDataLen = 0;
	kem_prm.pCipher         = NULL; // superfluous for encapsulate
	kem_prm.ulCipherLen     = 0;
	kem_prm.pBlob           = NULL; // used for hybrid
	kem_prm.ulBlobLen       = 0;

	mech.pParameter     = &kem_prm;
	mech.ulParameterLen = sizeof(kem_prm);

	rv = m_DeriveKey(&mech,
					 kyba, ARRAY_ELEMS(kyba),
					 pk, pklen,
					 NULL, ~0,
	                 NULL, ~0,
					 sspk, sspklen,
					 wrp, wrplen,
					 *target);

    if (rv != CKR_OK)
    {
    	printf("ERROR: m_DeriveKey...FAILED! rv = 0x%lx\n", rv);
    }

    return rv;
}





CK_RV kyber_decapsulate(target_t *target,
                                const unsigned char *sk,   size_t sklen,
								unsigned char *wrp, size_t wrplen,
								unsigned char *sssk, size_t *sssklen,
								unsigned char *cks, size_t *ckslen
								)
{
    CK_RV rv = CKR_OK;
    CK_MECHANISM mech = { .mechanism = CKM_IBM_KYBER };
	struct XCP_KYBER_KEM_PARAMS kem_prm = { 0 };
	size_t ct_offs = XCP_KEYBITS_FIELD_BYTES + PKCS11_CHECKSUM_BYTES;

	CK_ULONG dvktype = CKK_AES;
	CK_ULONG dvksize = 32;
	CK_ULONG kdftype = CKD_NULL;
	CK_ATTRIBUTE kyba[] = {
		{ CKA_KEY_TYPE,    (CK_VOID_PTR) &dvktype, sizeof(dvktype) },
		{ CKA_VALUE_LEN,   (CK_VOID_PTR) &dvksize, sizeof(dvksize) },
		{ CKA_EXTRACTABLE, (CK_VOID_PTR) &ltrue,   sizeof(lfalse)  },
	};

	kem_prm.kdf             = CKD_NULL;
	kem_prm.mode            = CK_IBM_KEM_DECAPSULATE;
	kem_prm.version         = XCP_KYBER_KEM_VERSION;
	kem_prm.pSharedData     = NULL;
	kem_prm.ulSharedDataLen = 0;
	kem_prm.pCipher         = wrp + ct_offs; // required for decapsulate
	kem_prm.ulCipherLen     = wrplen - ct_offs;
	kem_prm.pBlob           = NULL; // used in hybrid
	kem_prm.ulBlobLen       = 0;

	mech.pParameter     = &kem_prm;
	mech.ulParameterLen = sizeof(kem_prm);


	rv = m_DeriveKey(&mech,
					 kyba, ARRAY_ELEMS(kyba),
					 sk, sklen,
					 NULL, ~0,
	                 NULL, ~0,
					 sssk, sssklen,
					 cks, ckslen,
					 *target);

    if (rv != CKR_OK)
    {
    	printf("ERROR: m_DeriveKey...FAILED! rv = 0x%lx\n", rv);
    }

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
    printf("EP11 Kyber starts ...\n");


    int32_t module_nr = 1;  // TODO: Parse an argument to indicate which module
    int32_t domain_nr = 2;  // TODO: Parse an argument to indicate which domain

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
	if (rc != XCP_OK) {
        printf("Error creating target (rc=%d)\n", rc);
		return lib_shutdown(EXIT_FAILURE);
	}


     // Generate Dilithium Key Pair
    uint8_t prv[9000];
    size_t prv_len = sizeof(prv);
    uint8_t pub[9000];
    size_t pub_len = sizeof(pub);
    rv = generate_kyber_keypair(&target,
                        prv, &prv_len,
                        pub, &pub_len);
	if (rv != CKR_OK) {
        printf("Error creating Kyber keypair (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}

	// KEM encapsulate step
	unsigned char wrp[6144] = { 0 };
	unsigned char sspk[6144] = { 0 }; // shared-secret derive from pk
	size_t wrplen  = sizeof(wrp);
	size_t sspklen = sizeof(sspk);
	rv = kyber_encapsulate(&target, pub,   pub_len,
							wrp, &wrplen,
							sspk, &sspklen);
	if (rv != CKR_OK) {
        printf("Error Kyber encapsulate (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}


	// KEM decapsulate step
	unsigned char sssk[6144] = { 0 };
	unsigned char cks[PKCS11_CHECKSUM_BYTES + XCP_KEYBITS_FIELD_BYTES] = { 0 };
	size_t sssklen  = sizeof(sssk);
	size_t ckslen = sizeof(cks);
	rv = kyber_decapsulate(&target,
							prv,   prv_len,
							wrp, wrplen,
							sssk, &sssklen,
							cks, &ckslen);
	if (rv != CKR_OK) {
        printf("Error Kyber decapsulate (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}




	// Encrypt - Decrypt Test
	CK_MECHANISM enc_mech = { .mechanism = CKM_AES_CBC_PAD };
	enc_mech.mechanism = CKM_AES_CBC_PAD;
	unsigned char iv[ 16 ] = { 0,1,2,3,4,5,6,7,8,9 };
	enc_mech.pParameter = iv;
	enc_mech.ulParameterLen = sizeof(iv);
	unsigned char pln[ 16 ] = { 0 };
	unsigned char enc[ 512 ] = { 0 };
	unsigned char dec[ 512 ] = { 0 };
	size_t plnlen = sizeof(pln);
	size_t enclen = sizeof(enc);
	size_t declen = sizeof(dec);

	// Encrypt with the SSPK
	rv = m_EncryptSingle(sspk, sspklen, &enc_mech, pln, plnlen,
		                     enc, &enclen, target);
	if (rv != CKR_OK) {
        printf("Error encrypt (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}

	// Decrypt with the SSSK
	rv = m_DecryptSingle(sssk, sssklen, &enc_mech, enc, enclen,
		                     dec, &declen, target);
	if (rv != CKR_OK) {
        printf("Error decrypt (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}

	// Compare results
	if(memcmp(pln, dec, sizeof(pln)) != 0) {
		printf("Error Plaintext and decoded text do not match!\n");
		return lib_shutdown(EXIT_FAILURE);
	}


    printf("EP11 Kyber ends ...\n");
    return EXIT_SUCCESS;
}
