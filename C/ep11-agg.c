
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ep11.h>
#include <ctype.h>

#define ARRAY_ELEMS(arr)  (sizeof(arr) / sizeof((arr)[0]))
CK_BBOOL isTrue = CK_TRUE;
CK_BBOOL lFalse = CK_FALSE;



// Function to convert a hex string to a byte array
void hexStringToBytes(const char *hexStr, unsigned char *byteArray, size_t *byteArrayLen) {
    size_t hexLen = strlen(hexStr);
    *byteArrayLen = hexLen / 2; // Each byte is represented by 2 hex characters

    for (size_t i = 0; i < *byteArrayLen; i++) {
        sscanf(hexStr + 2 * i, "%2hhx", &byteArray[i]); // Read 2 hex chars and convert to a byte
    }

//    for (int i = 0; i < *byteArrayLen; i++) {
//        printf("byteArray[%d] = 0x%X\n", i, byteArray[i]);
//    }
}


CK_RV kyber_decapsulate(target_t *target
								)
{
    CK_RV rv = CKR_OK;

       CK_KEY_TYPE keyType = CKK_EC;
       CK_BYTE curve_name[] = {0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01,0x02,0x82,0x0B,0x87,0x67,0x03,0x02};
//06 0c 2b 06 01 04 01 02 82 0b 87 67 03 02

       CK_ULONG valueLen = 0;
       CK_ATTRIBUTE masterTmpl[] = {
        {CKA_KEY_TYPE,         &keyType,         sizeof(keyType) },
        {CKA_DERIVE,           &isTrue,          sizeof(isTrue) },
        {CKA_VERIFY,           &isTrue,          sizeof(isTrue) },
        {CKA_EC_PARAMS,        &curve_name,      sizeof(curve_name) },
        {CKA_IBM_USE_AS_DATA,  &isTrue,          sizeof(isTrue) },
    };

         CK_BYTE chainCode[32] = {};

	 char agg_str[] = "307d301706072a8648ce3d0201060c2b0601040102820b87670302036200040997e9dfc9f8d528b29faee287b851d62c6778bbf296a192867db18b411d92ed41c721d5cc41efe4ab930cfb57de71560a56b600cf700a08085b4cef40ba6aff130ac64c5c2a489efe65aa7f54f5a814362343200b39a282fb11fbb1499bcb57041050d94c73fbf3137d2239f132191026a5042000000000000000000000000000000000000000000000000000000000000000000408d3205283f93ad83c04080000000000000001041410010000000090a4000090a48001000a0000000104206e59c4cf8be4f7708d3cb493d4111561494b043c9008cdff0699075f5706f912307d301706072a8648ce3d0201060c2b0601040102820b87670302036200040408726378fa23f4547070a0ac16ac3ce802c31285788d487aa1dd6445d0dc521cd26786eaee102bc72502da8befebe00eb64c1707a1eeea98446670bb5665f63969590db49ca5f3918f80002ca55b544b1a8fd27f70722f16335f1dadec42f5041050d94c73fbf3137d2239f132191026a5042000000000000000000000000000000000000000000000000000000000000000000408e58bd46433f60ae404080000000000000001041410010000000090a4000090a48001000a0000000104204077184fc10fc069880eac3244281d3a38d9181256770dea9f7fbe9fe2f25e85";

    // Copy the string into heap memory

	  size_t byteArrayLen;
    unsigned char byteArray[strlen(agg_str) / 2]; // Allocate array size
    //unsigned char *byteArray = malloc(strlen(agg_str) / 2  + 1); // +1 for null terminator

    // Convert hex string to byte array
    hexStringToBytes(agg_str,byteArray , &byteArrayLen);
     printf("Byte array length: %zu\n", byteArrayLen);
     memset(chainCode, 0, 32);

     XCP_EC_AGGREGATE_PARAMS prm = {
	.perElementSize = 255,
	.ulElementsLen = 510,
        .version        = 0,
	.mode 		= 2,
	.pElements	= byteArray,
    };

    CK_MECHANISM mech = { 
	    .mechanism = CKM_IBM_EC_AGGREGATE, 
            .pParameter     = (CK_VOID_PTR)&prm,
            .ulParameterLen = sizeof(XCP_EC_AGGREGATE_PARAMS),
    };
//printf("%d ", prm.ulElementsLen);
  //  mech.pParameter     = (CK_VOID_PTR)&prm;
  //  mech.ulParameterLen = sizeof(XCP_EC_AGGREGATE_PARAMS);


unsigned char *data = (unsigned char *)mech.pParameter;
for (unsigned long i = 0; i < mech.ulParameterLen; i++) {
    printf("%02X ", data[i]);
}
printf("\n");

//printf("Address stored in pointer: %p\n" ,byteArray); 
//printf("Address stored in pointer: %p\n", ((XCP_EC_AGGREGATE_PARAMS *)mech.pParameter)->pElements);

data = ((XCP_EC_AGGREGATE_PARAMS *)mech.pParameter)->pElements;
for (unsigned long i = 0; i < ((XCP_EC_AGGREGATE_PARAMS *)mech.pParameter)->ulElementsLen; i++) {
//for (unsigned long i = 0; i < ((XCP_EC_AGGREGATE_PARAMS *)mech.pParameter)->perElementSize; i++) {
    printf("%02X ", data[i]);

}
    unsigned char sspk[6144] = { 0 };
    size_t sspklen = sizeof(sspk);
    unsigned char cks[6144] = { 0 };
    size_t ckslen = sizeof(cks);
printf("\n");
	rv = m_DeriveKey(&mech,
					 masterTmpl, ARRAY_ELEMS(masterTmpl),
					 NULL,0 ,
					 NULL, 0,
	                                 NULL, 0,
					 sspk, &sspklen,
					 cks, &ckslen,
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
	if (rc != XCP_OK) {
        printf("Error creating target (rc=%d)\n", rc);
		return lib_shutdown(EXIT_FAILURE);
	}

	rv = kyber_decapsulate(&target
							);
	if (rv != CKR_OK) {
        printf("Error (rv=0x%x)\n", rv);
		return lib_shutdown(EXIT_FAILURE);
	}



}
