package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>
#include <openssl/evp.h>
#include <stdlib.h>

*/
import "C"
import "ep11go/ep11"
import (
	"encoding/binary"
	"fmt"
//	"encoding/hex"
	"strings"
	"os"
	"strconv"
)

func printSKIs(payload []byte) {
    const skiSize = 32
    count := len(payload) / skiSize

    fmt.Printf("Detected %d full SKIs (SHA-256):\n", count)

    for i := 0; i < count; i++ {
        start := i * skiSize
        end := start + skiSize
        fmt.Printf("Admin %d SKI: %x\n", i+1, payload[start:end])
    }

    // Check for trailing data (if the payload was 92 instead of 96)
    if len(payload)%skiSize != 0 {
        remainder := payload[count*skiSize:]
        fmt.Printf("Trailing/Partial Data (%d bytes): %x\n", len(remainder), remainder)
    }
}

func PrintAdminAttributes(data []byte) {
    if len(data)%8 != 0 {
        fmt.Errorf("invalid attribute buffer length: %d", len(data))
	return
    }

    for i := 0; i < len(data); i += 8 {
        index := binary.BigEndian.Uint32(data[i : i+4])
        value := binary.BigEndian.Uint32(data[i+4 : i+8])

        fmt.Printf("%-25s = 0x%08x (%d)\n",
            adminAttrName(index),
            value,
            value,
        )
	if (index==3) {
		AnalysePermissions(value)
	}
    }

}

type Permission struct {
	Name  string
	Value uint32
}

func AnalysePermissions(perm uint32) {

	permissions := []Permission{
		// Base permissions
		{"XCP_ADMP_WK_IMPORT", 0x00000001},
		{"XCP_ADMP_WK_EXPORT", 0x00000002},
		{"XCP_ADMP_WK_1PART", 0x00000004},
		{"XCP_ADMP_WK_RANDOM", 0x00000008},
		{"XCP_ADMP_1SIGN", 0x00000010},
		{"XCP_ADMP_CP_1SIGN", 0x00000020},
		{"XCP_ADMP_ZERO_1SIGN", 0x00000040},
		{"XCP_ADMP_NO_DOMAIN_IMPRINT", 0x00000080},
		{"XCP_ADMP_STATE_IMPORT", 0x00000100},
		{"XCP_ADMP_STATE_EXPORT", 0x00000200},
		{"XCP_ADMP_STATE_1PART", 0x00000400},
		{"XCP_ADMP_NO_EPX", 0x00000800},
		{"XCP_ADMP_NO_EPXVM", 0x00001000},
		{"XCP_ADMP_DO_NOT_DISTURB", 0x00002000},

		// Change permissions
		{"XCP_ADMP_CHG_WK_IMPORT", 0x00010000},
		{"XCP_ADMP_CHG_WK_EXPORT", 0x00020000},
		{"XCP_ADMP_CHG_WK_1PART", 0x00040000},
		{"XCP_ADMP_CHG_WK_RANDOM", 0x00080000},
		{"XCP_ADMP_CHG_SIGN_THR", 0x00100000},
		{"XCP_ADMP_CHG_REVOKE_THR", 0x00200000},
		{"XCP_ADMP_CHG_1SIGN", 0x00400000},
		{"XCP_ADMP_CHG_CP_1SIGN", 0x00800000},
		{"XCP_ADMP_CHG_ZERO_1SIGN", 0x01000000},
		{"XCP_ADMP_CHG_ST_IMPORT", 0x02000000},
		{"XCP_ADMP_CHG_ST_EXPORT", 0x04000000},
		{"XCP_ADMP_CHG_ST_1PART", 0x08000000},
		{"XCP_ADMP_CHG_NO_EPX", 0x20000000},
		{"XCP_ADMP_CHG_NO_EPXVM", 0x40000000},
		{"XCP_ADMP_CHG_DO_NOT_DISTURB", 0x80000000},
	}

	var enabled []string

	for _, p := range permissions {
		if perm&p.Value != 0 {
//			fmt.Printf("✔ %s (0x%08X)\n", p.Name, p.Value)
			enabled = append(enabled, p.Name)
		}
	}

	// Print all enabled permissions as a single | separated string
	if len(enabled) > 0 {
		fmt.Printf("    %s\n",strings.Join(enabled, " | "))
	}
}


func adminAttrName(index uint32) string {
    switch index {
    case 1:
        return "XCP_ADMINT_SIGN_THR"
    case 2:
        return "XCP_ADMINT_REVOKE_THR"
    case 3:
        return "XCP_ADMINT_PERMS"
    case 4:
        return "XCP_ADMINT_MODE"
    case 5:
        return "XCP_ADMINT_STD"
    case 6:
        return "XCP_ADMINT_PERMS_EXT01"
    case 7:
        return "XCP_ADMINT_GEN_KTYPES"
    case 8:
        return "XCP_ADMINT_ECC_KTYPES"
    case 9:
        return "XCP_ADMINT_DIL_KTYPES"
    case 10:
        return "XCP_ADMINT_ADM_COMPL"
    default:
        return fmt.Sprintf("UNKNOWN_%d", index)
    }
}


func main() {
        if len(os.Args) != 3 {
                fmt.Fprintf(os.Stderr, "usage: %s <control-domain> <domain>\n", os.Args[0])
                os.Exit(1)
        }

        // 1) Control domain (e.g. "3.19")
        controlDomain := os.Args[1]

        // 2) Target domain (e.g. 16)
        domain64, err := strconv.ParseUint(os.Args[2], 10, 32)
        domain := uint32(domain64)
        if err != nil {
                fmt.Fprintf(os.Stderr, "invalid domain: %v\n", err)
                os.Exit(1)
        }

        target := ep11.HsmInit(controlDomain) 
	
	cert1hex :="3082031d30820205a003020102021436a0469cb1f1e29e223e2efc23fff63b2266b77e300d06092a864886f70d01010b05003011310f300d060355040a0c064d59434f5250301e170d3236303231393038333933315a170d3236303831383038333933315a3011310f300d060355040a0c064d59434f525030820122300d06092a864886f70d01010105000382010f003082010a0282010100e7f78621e9221dcb65d4db584fbb92033c3db47089026f91485af843c36a5089ff76e7febe13d896d66dc2106624eeeabd226f9fb0777666158c8106e5b26fb198558b169013f913f11eda5d4291eb34bb85b2d8acfe510bf912b9eb4321725487f901cb97bf9cf42777872bc6af6676ce21e7e77e2be6fddb11f5998d7f579c01b5268bb251d3a88f9b76d2ec9d41e4c321d699942e1f097ce5ee60e712797d9a99997cf69de601942ef4cebda63892197799817b2730f2957eaac1e9361e4b5e1e3995723af067bde3fc76771d73903d3b94b1268f61130b7a5aa792fa13046beba324c72f845d03d543da973d84ff8a1307f24bba5883e1beb5045d46e9bb0203010001a36d306b300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030202a430130603551d25040c300a06082b0601050507030130140603551d11040d300b82096c6f63616c686f7374301d0603551d0e04160414e6ca8abaa53aaac856c98ed87bbb0925346bc3e1300d06092a864886f70d01010b050003820101001969fd0c0422be8a5d6d4d236b3b04a681d59273c919611ffe6573683096b1804ee13842868ee39b2164fdf9b9417816f10e5f5f021386e0a642e27a240b51576d22d06b055aae822aaa8c50d220f689c80c96b5892a739e3e3cbf54cf057600b7f290244353a6313f6f557963563c1914f513b649881a75eff861a6058ae822f8a5f6201d187f949b55708f4058fcbc2a489b0cddb8ec57e4011ef611173ce6d350c98a5b7c55fc25898dd2b4e7145aee8352204216de14a6c3315525242212d26f912571ef11122bc75612de92ba56b8bb910191e546ff14d97157a082d65cfe52703da5eddcf8b2ddc816b5749d003fa5d10fe75703a44213e8e50d5c8700"

	privadmin1hex:="2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d494945766749424144414e42676b71686b6947397730424151454641415343424b67776767536b41674541416f49424151446e3934596836534964793258550a32316850753549445044323063496b4362354649577668447732705169663932352f362b45396957316d33434547596b37757139496d2b66734864325a68574d0a6751626c736d2b786d46574c467041542b52507848747064517048724e4c7546737469732f6c454c2b524b3536304d68636c53482b51484c6c372b63394364330a6879764772325a327a69486e35333472357633624566575a6a5839586e4147314a6f757955644f6f6a35743230757964516554444964615a6c43346643587a6c0a376d446e456e6c396d706d5a66506164356747554c76544f766159346b686c336d5946374a7a44796c58367177656b32486b7465486a6d56636a72775a37336a0a2f485a3348584f51505475557353615059524d4c656c716e6b766f54424776726f7954484c345264413956443270633968502b4b4577667953377059672b472b0a7451526452756d3741674d424141454367674541546d47386144372f73544f6d6743747942746370756f416a6c5a496c4b62614c542f693152536947427872710a514d4b5a754a36364a42586d31706c312b6d726b314f344b36396e554e4354416955366342776570614568434e354a7a4d74794b57594b455a4e6a32743553450a2f4f4e334264575669306370686273795874336b4a474947736b58666b47694c345837435577753377744e6162364d775a694e53696a44695858574c6e77314b0a54517147765644536d35333952514f46334148624b47662b536e35585542524a564e766a346a2b526b324a69677a5a6e386d517a6f67473731793936455649640a5a35397a644b6c4f4e773547327572642f597636526f33485a7357645273383865694d4c456f724f4745394e50614e6e4d56674f5773655443677758547063470a6a696f6f336b715261774d544d672f3164624d334c647430692b595549704950783461795851796969514b426751442b4d63554c364d77436e577565464279440a44544c39415a386a4272772f586a5638677951665338475247336a7775436f556559676937694a4a793969686a6363374d6e592f2b54305066554453324c43730a37664e6b56692f686b4b564a6c70414578545777427970502b2b554464764250773953644f514a4b366b4662595353314f5a393230727838485434304255746c0a553847654c67596c356835463937334b684c6c624969784837514b42675144706e5658665271716f3439512f774b5175395556554a4273436e63364a564c764e0a49314a35426b6e6b69372b68634b6a4743716533503869794b7745313533346f656c506d636c743678354e663543436c634b5065776d4a6f6b516c737a7757750a334b35537262536a4a2f794e58346a6d765643796d497179316257546e4c2f6c2f46396f756a52446938777270786967754b6a4c466f7352744d43586b6a7a4d0a543035614c48337a52774b42675144336f726a6158314c516756666b537164304c4a6d747a625367784f45447774334d6a5633566431483938597569783265480a527461505950726164644a336f4d326c4b41583355504a6863703643536b506b56485133485a664c34635345716a396e786c4146537857336b69694c645957720a7a3559454452506b733834304862464c4d2f58634a6e556c584c2f4b6f685850677763752b4a7459744a5274695772474c774c386535413043514b42675143320a7275754538327a6e4c326f2b42485966706e7431686470395845777a686b687037584a443439414b3465475437465a2b7237786868345a3546546f59486850410a735a424569433754503567576833326b41676154587579336d7075464e4172637141504638634a74534171747677522b63354c555a6f636e76416b4843712f680a75453466786d537959584c6976414e3951346e7a626f69483678496b4e5235494973684271634e415a774b42674376447647673037542b5242456d50647073580a66475979764d72422b396838517342456f636e534b362b61373373764e71424f6b646b746c43724c446873746a344a47523765696a57353639743448507165380a634a674f695547576c56696c4e6661383770476461636832416453324b424452334d396a4f57377455786e417549524e7163675a65456b4b486a4877474379540a4e74362b716d2b4b4b44466d3044366179485157374d432b0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a"  
	_ = cert1hex
	_ = privadmin1hex
/*
	privadmin1Bytes, err := hex.DecodeString(privadmin1hex)
        cert1Bytes, err := hex.DecodeString(cert1hex)

	resp , err:= ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_ADMIN_LOGIN,cert1Bytes,nil)        
        if err != nil {    
            fmt.Println(err)
        }
	printSKIs(resp.Response)
	fmt.Println()

// **********************************************************************************************************************
// LOGIN/ADD
// **********************************************************************************************************************
	cert1hex = "3082051f30820307a0030201020214118da053b569c779545d58998142f8bc26ee4bcc300d06092a864886f70d01010b05003011310f300d060355040a0c064d59434f52503020170d3236303231393039333032365a180f32353138313231373039333032365a3011310f300d060355040a0c064d59434f525030820222300d06092a864886f70d01010105000382020f003082020a02820201009b2e455c6283f6b9943791c80ba9826055ee01fd5954d9b4c64602b31afc68b0190aa9e1cb335e36bcc81cbc4d1849decba1df85fca91cdffde3046a8623875677c55454287f47768dd93dac4ab16a01355016b4ee95e87802d8256da84d63579cfc596b76642cddedcd2253a1bfc8949b5c0076d2bafce842d587f6317b9537c91d9cb67e03d4f586854e298911d036430edec262cf2f975047fc7e355d87be40e2ca1de47649b49e4bb92f40a3d43ab910521046e138278b7c3b0b6e887450387e84242147ed300f617a1336dc7544fbf95aa857334158c5c1d86e35c6b2952a3d90bfc2337592d0cdf12e0fbdc4af5209259559d23c7587babd624fae196311e32208a023d1c80df10d4480f7289ce5ed29826d336098442255698f1ab4e8524dcb31cf1006f76613747d3fc214489489bdd3ea1b0b3845f8f5d78bc5e1899f160f3517367349aa6802ed91403ae2436bddad0df427d1ca3b0bc657220bc7d31de1e72b777b2ec13b4760141d9fb29cd4fb21b7753832108379cbda4ee4b3858def7f5acd1019a2eafd7730a02d7090ba106c3975bb20293cd325de39bee4996a99657378f20cc9d65143663faface72903bdadcba60db88fdb48e97f11f673fd00873c9028600ec57be7dd6bbdd4e3cc5980bb25f944e2064f97e73ef23dd433ca5b4f4c5ec266b5fbee6f01d5b35392bf313e6d8a7407d0307bcfd432510203010001a36d306b300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030202a430130603551d25040c300a06082b0601050507030130140603551d11040d300b82096c6f63616c686f7374301d0603551d0e04160414fe6e65b6c440bbea8d6cd9c0567c9c3ac6ac1dfe300d06092a864886f70d01010b0500038202010065ec14695736bfc4d12da65d3d89af2721acdd5f5a2994006f654cfc1a49a01d5ccd2429a4dfa431728e30c18cd4ff243136ad38b34b3d7de993f446f6151831fbf1499e42f08dbaf63cbe89565ba9eeb421d375c220bba960c678b23a1c30a70908d6ec316f69e33d678a7a48bfca1355ab09fcd40a544f55e9dd83143974edb87539bbffeaca34a9bbed85d7457924a9c004da3b9de7f211a20244d834af24040403b92c49db80aba277a9357e7c0cb6e6b071d2ea2391db75e563a3ef63c33f0360089f1cba394998d9ec72b7db87f38641a9c0cc06a376fcf3327e818f4bd49a118f36a955d0f455b3b0f0f12281095018bf8859e91b85a51a1b0dc77d753881e8f1a64e9dd7c7c4d80952b12131cecebdb98036795cd73f235b0f95cb8b3b7902061e82bce1a509811863ddd3a5bc67246c53481ebe16977149dec054a08d873f3acd7a6ea0ae8719325e83b1ac95af00ab1c1b9fd11b531ff4d9090608faa3e134da22ccf99a7a2ff3cfd0de2e8f68553046130aebd7f5670d0cf5543abe2160d95c94f0343aa160c8d7f7114546d2f3c80d7bcec4835220393065bbf9670f5789c007d5d5a1bf04722c411914af0868597db621f7222825904ecfdf4bd85f44d6e74c059eab5f5891eff14c5d0fa3e674730476c16cd7ab85a0470666d2d92c5e421e82881764432c5e977c9423bf9aba01a2e9bb084a6bb11064263c"

        cert1Bytes, err = hex.DecodeString(cert1hex)
	if err != nil {
        	fmt.Println("Failed to decode hex string: %v", err)
		return
    	}

	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_ADMIN_LOGIN,cert1Bytes,nil)        
//	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_ADMIN_LOGIN,cert1Bytes,nil)        
        if err != nil {    
            fmt.Println(err)
        }
	printSKIs(resp.Response)
	fmt.Printf("Domain:           %X\n", resp.Domain)
	fmt.Printf("ModuleIdentifier: %X\n", resp.ModuleIdentifier)
	fmt.Printf("TransactionCtr:   %X\n", resp.TransactionCtr)
	fmt.Println()


// **********************************************************************************************************************
// LOGOUT/REMOVE
// **********************************************************************************************************************
	ski1hex := "6d18f4f7b33b6353e773631e4b35cb93663f65bf10e6522a1e165f64464e7e7e"
        ski1Bytes, err := hex.DecodeString(ski1hex)
	if err != nil {
        	fmt.Println("Failed to decode hex string: %v", err)
		return
    	}

	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_ADMIN_LOGOUT,ski1Bytes,nil)        
        if err != nil {    
            fmt.Println(err)
        }
	printSKIs(resp.Response)
	fmt.Println()



// **********************************************************************************************************************
// QUERY ATTRIBUTES
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOM_ATTRS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	fmt.Printf("Domain attributes\n")
	PrintAdminAttributes(resp.Response)
*/


// **********************************************************************************************************************
// LIST ADMIN SKIs
// **********************************************************************************************************************
	resp , err := ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOMADMIN)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	printSKIs(resp.Response)

	 
// **********************************************************************************************************************
// SCAN CARD ATTRIBUTES
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_ATTRS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	fmt.Printf("Adapter attributes\n")
	PrintAdminAttributes(resp.Response)
	
// **********************************************************************************************************************
// SCAN DOMAIN ATTRIBUTES
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOM_ATTRS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	fmt.Printf("Domain attributes\n")
	PrintAdminAttributes(resp.Response)
	
// **********************************************************************************************************************
// SCAN MEK MKVPS
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_WK_ORIGINS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Printf("\nKey Parts pattern         %x\n", resp.Response)
	
/*
	fmt.Printf("AdmFunctionId:    %X\n", resp.AdmFunctionId)
	fmt.Printf("Domain:           %X\n", resp.Domain)
	fmt.Printf("ModuleIdentifier: %X\n", resp.ModuleIdentifier)
	fmt.Printf("TransactionCtr:   %X\n", resp.TransactionCtr)
	fmt.Printf("ResponseCode:     %X ", resp.ResponseCode)
*/
	
//	fmt.Printf("Response:          %X\n", resp.Response)
//	fmt.Println("---------------------------------")

}
