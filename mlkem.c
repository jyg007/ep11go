/*----------------------------------------------------------------------
 *
 * Licensed Materials - Property of IBM
 *
 * IBM Z Enterprise PKCS #11 (EP11) Support Program
 *
 * (C) Copyright IBM Corp. 2025
 *
 *-------------------------------------------------------------------
 *                                                                   
 *  These samples are provided to assist in debug functions.         
 *  This source is distributed on an "as-is" basis,                  
 *  without any warranties either expressed or implied.              
 *                                                                   
 *----------------------------------------------------------------------
 *  LINUX on S390
 *
 *  Example is written for Linux on z Systems
 *
 *----------------------------------------------------------------------
 *  EP11 support e-mail address: EP11SUPP@de.ibm.com
 *
 *  Use this e-mail address for Bugs and Comments with the EP11 product.
 *----------------------------------------------------------------------*/

/**************************************************************************
 *
 * Example ML-KEM application using the ep11 host library under linux
 *
 **************************************************************************
 * Adapt the definitions TARGET_AP and USAGE_DOMAIN below according to your
 * configuration
 *
 * Compile with: gcc -o mlkem_ep11_app mlkem_ep11_app.c $(pkg-config --libs --cflags ep11)
 *
 * An additional include path might be required on platforms where the pkcs11.h
 * include file is not available in the standard include paths.
 *
 * For example the pkcs11 header files from openCryptoki can be used:
 *
 * gcc -o mlkem_ep11_app mlkem_ep11_app.c -I/usr/include/opencryptoki $(pkg-config --libs --cflags ep11)
 */

#include <stdio.h>
#include <stdint.h>
//#include <pkcs11.h>
#include <ep11.h>
#include <string.h>
#include <ep11adm.h>

// Adapt the define values as required for your configuration!
#define TARGET_AP 0
#define USAGE_DOMAIN 8

#define MLKEM_KEY_MAX_BYTES 10000
#define AES_KEY_MAX_BYTES  (256/8)
#define INITIAL_VECTOR_BUFF 16
#define PLAIN_DATA_BYTES 1024

#define ARRAY_ELEMS(arr) (sizeof(arr) / sizeof((arr)[0]))

//-------------------------------------
// returns rc or -1, depending on success or failure of shutting down backend
//
static int lib_shutdown(int rc)
{
        if (m_shutdown() != XCP_OK)
        {
                fprintf(stderr, "error: can not shutdown EP11 library\n");
                return -1;
        }

        printf("===  EP11 library successfully shutdown  ============\n");

        return rc;
}


int memdiffer(const void *r1, size_t r1len, const void *r2, size_t r2len)
{
	if ((NULL == r1) || (NULL == r2)) {
		printf("Buffers to compare are NULL\n");
		return -1;
	}

	if (r1len != r2len) {
		printf("length mismatch: %zu/%zu\n", r1len, r2len);
		return -1;
	}

	return (memcmp(r1, r2, r1len));
}


int main(void)
{
        // target token variable used to specify AP/domain pairs
        // always initialize target tokens with XCP_TGT_INIT
        target_t target = XCP_TGT_INIT;

        /* An XCP module is a abstract description of for example a crypto
         * express card. It contains all information that is needed to
         * communicate with a card.
         *
         * The version field guarantees backward compatibility. Applications
         * compiled against older versions of the host library will observe only
         * features applicable to the version when they were compiled.
         */
        struct XCP_Module module = {.version = XCP_MOD_VERSION};

        /* some non PKCS#11 functions do only return a return code and
         * no CKR value. The codes are described in ep11.h
         */
        int rc;

        CK_RV rv;
        CK_BYTE qresp[4];
        CK_ULONG qbytes;
        uint32_t *qresp_u32 = (uint32_t *)qresp;

        CK_MECHANISM mlkem_keygen_mech, mlkem_derive_mech, enc_dec_mech;

        unsigned char priv[MLKEM_KEY_MAX_BYTES],
                      pub[MLKEM_KEY_MAX_BYTES],
                      first_shared_sec[MLKEM_KEY_MAX_BYTES],
                      second_shared_sec[MLKEM_KEY_MAX_BYTES],
                      first_cipher[MLKEM_KEY_MAX_BYTES],
                      second_cipher[MLKEM_KEY_MAX_BYTES],
                      plain_data[PLAIN_DATA_BYTES],
                      iv[INITIAL_VECTOR_BUFF],
                      enc[AES_KEY_MAX_BYTES],
                      dec[AES_KEY_MAX_BYTES];;
        size_t priv_len = sizeof(priv),
               pub_len = sizeof(pub),
               first_shared_seclen = sizeof(first_shared_sec),
               second_shared_seclen = sizeof(second_shared_sec),
               first_cipherlen = sizeof(first_cipher),
               second_cipherlen = sizeof(second_cipher),
               plain_data_len = sizeof(plain_data),
               enc_len = sizeof(enc),
               dec_len = sizeof(dec);
        CK_BBOOL ltrue = CK_TRUE;
        CK_ULONG dvktype = CKK_AES;
        CK_ULONG dvksize = 32;
        CK_IBM_ML_KEM_PARAMETER_SET_TYPE param_set_type;
        struct XCP_KYBER_KEM_PARAMS kem_prm = {0};
        size_t ext_bytes = XCP_KEYBITS_FIELD_BYTES + PKCS11_CHECKSUM_BYTES;
        param_set_type = CKP_IBM_ML_KEM_512;
        unsigned char mlkem_strengths[512] = { 0 };
	CK_ULONG mlkem_strengths_len = 0;
        CK_MECHANISM_INFO keygen_mech_info = { 0 };
	CK_MECHANISM_INFO derive_mech_info = { 0 };

        CK_ATTRIBUTE pub_attrs[] = {
            { CKA_DERIVE,            &ltrue,          sizeof(ltrue)          },
            { CKA_IBM_PARAMETER_SET, &param_set_type, sizeof(param_set_type) },
        };

        CK_ATTRIBUTE priv_attrs[] = {
            { CKA_DERIVE, &ltrue, sizeof(ltrue) },
        };

        CK_ATTRIBUTE attrb[] = {
            {CKA_KEY_TYPE,        (CK_VOID_PTR)&dvktype, sizeof(dvktype)},
            {CKA_VALUE_LEN,       (CK_VOID_PTR)&dvksize, sizeof(dvksize)},
            {CKA_EXTRACTABLE,     (CK_VOID_PTR)&ltrue,   sizeof(ltrue)  },
        };

        rc = m_init();
        if (rc != XCP_OK)
        {
                fprintf(stderr, "Could not init ep11 library: rc: %d\n", rc);
                return -1;
        }

        printf("=== EP11 library initialization successful =============\n");

        /* CK_IBM_XCPHQ_TGT_MODE: query hostlib target mode
         *
         * host queries not required to set up module/target
         * (no communication with the card)
         */
        memset(qresp, 0, sizeof(qresp));
        qbytes = sizeof(qresp);
        rv = m_get_xcp_info((CK_VOID_PTR)qresp, &qbytes,
                            CK_IBM_XCPHQ_TGT_MODE, 0, target);

        if (rv != CKR_OK)
        {
                fprintf(stderr, "Could not query module: rv: 0x%08lx\n", rv);
                return lib_shutdown(-1);
        }

        // (host) query responses are always big endian order. Convert it, if
        // the system is little endian

        if (*qresp_u32 != CK_IBM_XCPHQ_TGT_MODES_TGTGRP)
        {
                fprintf(stderr, "error: unknown target mode %u\n", *qresp_u32);
                return lib_shutdown(-1);
        }

        // Example (see defines above) target AP: 0 Usage domain: 5
        // Creates a target token in single notation in built-in group zero
        module.module_nr = 3;
        XCPTGTMASK_SET_DOM(module.domainmask, 19);

        // set flags for queue system and probe of target
	// probe checks if card with domain is available
	// if probe is not set domain will always be set
        module.flags |= XCP_MFL_MODULE | XCP_MFL_PROBE;
        rc = m_add_module(&module, &target);
        if (rc != XCP_OK)
        {
                fprintf(stderr, "Could not create single target: rc: %d\n", rc);
                return lib_shutdown(-1);
        }

        rv = m_GetMechanismInfo(0, CKM_IBM_ML_KEM_KEY_PAIR_GEN, &keygen_mech_info, target);
	if (rv == CKR_MECHANISM_INVALID) {
	    fprintf(stderr, "ML-KEM keygen mechanism is not available\n");
	    return lib_shutdown(-1);
	}

	if (rv == CKR_OK) {
	    printf("ML-KEM keygen mechanism(CKM_IBM_ML_KEM_KEY_PAIR_GEN) is available\n");
	    printf("Keygen flags: 0x%08lx\n", keygen_mech_info.flags);
	    printf("Min key-size(bytes): %ld\n", keygen_mech_info.ulMinKeySize);
	    printf("Max key-size(bytes): %ld\n", keygen_mech_info.ulMaxKeySize);
	}

	rv = m_GetMechanismInfo(0, CKM_IBM_ML_KEM, &derive_mech_info, target);
	if (rv == CKR_MECHANISM_INVALID) {
	    fprintf(stderr, "ML-KEM derive mechanism is not available\n");
	    return lib_shutdown(-1);
	}

	if (rv == CKR_OK) {
	    printf("ML-KEM derive mechanism(CKM_IBM_ML_KEM) is available\n");
	    printf("derive flags: 0x%08lx\n", derive_mech_info.flags);
	}

	mlkem_strengths_len = sizeof(mlkem_strengths);
	rv = m_get_xcp_info((CK_VOID_PTR)mlkem_strengths, &mlkem_strengths_len,
	                    CK_IBM_XCPQ_PQC_STRENGTHS, 0, target);
	if (rv != CKR_OK) {
	    fprintf(stderr, "Could not query PQC strengths: rv: 0x%08lx\n", rv);
	    return lib_shutdown(-1);
	}

	if (rv == CKR_OK) {
	    printf("PQC strengths query(CK_IBM_XCPQ_PQC_STRENGTHS) is available\n");
	    rc = xcpa_bitmask_has_bit(mlkem_strengths, mlkem_strengths_len, XCP_PQC_S_ML_KEM_512 - 1);
	    if (rc <= 0) {
	        fprintf(stderr, "This version of ML-KEM is not unsupported\n");
	        return lib_shutdown(-1);
	    } else {
	        printf("ML-KEM strength of XCP_PQC_S_ML_KEM_512 is supported\n");
	    }
	}

        mlkem_keygen_mech.mechanism = CKM_IBM_ML_KEM_KEY_PAIR_GEN;

        param_set_type = CKP_IBM_ML_KEM_512;

        rv = m_GenerateKeyPair(&mlkem_keygen_mech,
                               pub_attrs, ARRAY_ELEMS(pub_attrs),
                               priv_attrs, ARRAY_ELEMS(priv_attrs),
                               NULL, 0, /* no pin blob */
                               priv, &priv_len, pub, &pub_len, target);

        if (rv != CKR_OK)
        {
                fprintf(stderr, "Could not generate ML-KEM key: rv: 0x%08lx\n", rv);
                return lib_shutdown(-1);
        }

        printf("ML-KEM keypair generated successfully\n");

        mlkem_derive_mech.mechanism = CKM_IBM_ML_KEM;

        //kem_prm structure for encapsulation
        kem_prm.kdf = CKD_NULL; //key derivation function
        kem_prm.mode = CK_IBM_KEM_ENCAPSULATE; //encapsulation mode
        kem_prm.version = XCP_KYBER_KEM_VERSION;
        kem_prm.pSharedData = NULL;
        kem_prm.ulSharedDataLen = 0;
        kem_prm.pCipher = NULL; 
        kem_prm.ulCipherLen = 0;
        kem_prm.pBlob = NULL;
        kem_prm.ulBlobLen = 0;

        mlkem_derive_mech.pParameter = &kem_prm;
        mlkem_derive_mech.ulParameterLen = sizeof(kem_prm);

        rv = m_DeriveKey(&mlkem_derive_mech, attrb, ARRAY_ELEMS(attrb), pub, pub_len,
                         NULL, ~0, NULL, ~0, first_shared_sec, &first_shared_seclen,
                         first_cipher, &first_cipherlen, target);
        if (rv != CKR_OK)
        {
                fprintf(stderr, "Could not derive encp shared serect: rv: 0x%08lx\n", rv);
                return lib_shutdown(-1);
        }

        printf("ML-KEM first shared secret derived successfully\n");

        //kem_prm structure for decapsulation
        kem_prm.kdf = CKD_NULL; //key derivation function
        kem_prm.mode = CK_IBM_KEM_DECAPSULATE; //decapsulation mode
        kem_prm.version = XCP_KYBER_KEM_VERSION;
        kem_prm.pSharedData = NULL;
        kem_prm.ulSharedDataLen = 0;
        kem_prm.pCipher = first_cipher + ext_bytes; // required for decapsulate
        kem_prm.ulCipherLen = first_cipherlen - ext_bytes;
        kem_prm.pBlob = NULL;
        kem_prm.ulBlobLen = 0;

        mlkem_derive_mech.pParameter = &kem_prm;
        mlkem_derive_mech.ulParameterLen = sizeof(kem_prm);

        rv = m_DeriveKey(&mlkem_derive_mech, attrb, ARRAY_ELEMS(attrb), priv, priv_len,
                         NULL, ~0, NULL, ~0, second_shared_sec, &second_shared_seclen,
                         second_cipher, &second_cipherlen, target);

        if (rv != CKR_OK)
        {
                fprintf(stderr, "Could not derive decap shared serect: rv: 0x%08lx\n", rv);
                return lib_shutdown(-1);
        }

        printf("ML-KEM second shared secret derived successfully\n");

        enc_dec_mech.mechanism = CKM_AES_CBC_PAD;
        enc_dec_mech.pParameter = iv;
        enc_dec_mech.ulParameterLen = sizeof(iv);
        
        rv = m_EncryptSingle(first_shared_sec, first_shared_seclen, &enc_dec_mech,
                             plain_data, plain_data_len, enc, &enc_len, target);
                             
        if (rv != CKR_OK) {
                fprintf(stderr, "Could not encrypt the data: rv: 0x%08lx\n", rv);
                return lib_shutdown(-1);
        }
        
        printf("Data encrypted with ML-KEM derived key successfully\n");

        rv = m_DecryptSingle(second_shared_sec, second_shared_seclen, &enc_dec_mech,
                             enc, enc_len, dec, &dec_len, target);
        
        if (rv != CKR_OK) {
                fprintf(stderr, "Could not decrypt the data: rv: 0x%08lx\n", rv);
                return lib_shutdown(-1);
	}
        
        printf("Data decrypted with ML-KEM derived key successfully\n");

        rc = memdiffer(plain_data, plain_data_len, dec, dec_len);

	if (rc != 0) {
		fprintf(stderr, "input data and decrypted data does not match: %d\n", rc);
		return lib_shutdown(-1);
	}

        printf("Operations on shared secret keys successful\n");

        rc = m_rm_module(NULL, target);
        if (rc != XCP_OK)
        {
                fprintf(stderr, "Could not remove target group: rc: %d\n", rc);
                return lib_shutdown(-1);
        }

        return lib_shutdown(0);
}

