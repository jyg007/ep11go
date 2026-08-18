package ep11

import(
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/asn1"
    "encoding/hex"
    "flag"
    "fmt"
    "io"
    "os"
    "math/big"
)

const DefaultCertHex = "3082031d30820205a003020102021436a0469cb1f1e29e223e2efc23fff63b2266b77e300d06092a864886f70d01010b05003011310f300d060355040a0c064d59434f5250301e170d3236303231393038333933315a170d3236303831383038333933315a3011310f300d060355040a0c064d59434f525030820122300d06092a864886f70d01010105000382010f003082010a0282010100e7f78621e9221dcb65d4db584fbb92033c3db47089026f91485af843c36a5089ff76e7febe13d896d66dc2106624eeeabd226f9fb0777666158c8106e5b26fb198558b169013f913f11eda5d4291eb34bb85b2d8acfe510bf912b9eb4321725487f901cb97bf9cf42777872bc6af6676ce21e7e77e2be6fddb11f5998d7f579c01b5268bb251d3a88f9b76d2ec9d41e4c321d699942e1f097ce5ee60e712797d9a99997cf69de601942ef4cebda63892197799817b2730f2957eaac1e9361e4b5e1e3995723af067bde3fc76771d73903d3b94b1268f61130b7a5aa792fa13046beba324c72f845d03d543da973d84ff8a1307f24bba5883e1beb5045d46e9bb0203010001a36d306b300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030202a430130603551d25040c300a06082b0601050507030130140603551d11040d300b82096c6f63616c686f7374301d0603551d0e04160414e6ca8abaa53aaac856c98ed87bbb0925346bc3e1300d06092a864886f70d01010b050003820101001969fd0c0422be8a5d6d4d236b3b04a681d59273c919611ffe6573683096b1804ee13842868ee39b2164fdf9b9417816f10e5f5f021386e0a642e27a240b51576d22d06b055aae822aaa8c50d220f689c80c96b5892a739e3e3cbf54cf057600b7f290244353a6313f6f557963563c1914f513b649881a75eff861a6058ae822f8a5f6201d187f949b55708f4058fcbc2a489b0cddb8ec57e4011ef611173ce6d350c98a5b7c55fc25898dd2b4e7145aee8352204216de14a6c3315525242212d26f912571ef11122bc75612de92ba56b8bb910191e546ff14d97157a082d65cfe52703da5eddcf8b2ddc816b5749d003fa5d10fe75703a44213e8e50d5c8700"

const DefaultKeyHex = "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d494945766749424144414e42676b71686b6947397730424151454641415343424b67776767536b41674541416f49424151446e3934596836534964793258550a32316850753549445044323063496b4362354649577668447732705169663932352f362b45396957316d33434547596b37757139496d2b66734864325a68574d0a6751626c736d2b786d46574c467041542b52507848747064517048724e4c7546737469732f6c454c2b524b3536304d68636c53482b51484c6c372b63394364330a6879764772325a327a69486e35333472357633624566575a6a5839586e4147314a6f757955644f6f6a35743230757964516554444964615a6c43346643587a6c0a376d446e456e6c396d706d5a66506164356747554c76544f766159346b686c336d5946374a7a44796c58367177656b32486b7465486a6d56636a72775a37336a0a2f485a3348584f51505475557353615059524d4c656c716e6b766f54424776726f7954484c345264413956443270633968502b4b4577667953377059672b472b0a7451526452756d3741674d424141454367674541546d47386144372f73544f6d6743747942746370756f416a6c5a496c4b62614c542f693152536947427872710a514d4b5a754a36364a42586d31706c312b6d726b314f344b36396e554e4354416955366342776570614568434e354a7a4d74794b57594b455a4e6a32743553450a2f4f4e334264575669306370686273795874336b4a474947736b58666b47694c345837435577753377744e6162364d775a694e53696a44695858574c6e77314b0a54517147765644536d35333952514f46334148624b47662b536e35585542524a564e766a346a2b526b324a69677a5a6e386d517a6f67473731793936455649640a5a35397a644b6c4f4e773547327572642f597636526f33485a7357645273383865694d4c456f724f4745394e50614e6e4d56674f5773655443677758547063470a6a696f6f336b715261774d544d672f3164624d334c647430692b595549704950783461795851796969514b426751442b4d63554c364d77436e577565464279440a44544c39415a386a4272772f586a5638677951665338475247336a7775436f556559676937694a4a793969686a6363374d6e592f2b54305066554453324c43730a37664e6b56692f686b4b564a6c70414578545777427970502b2b554464764250773953644f514a4b366b4662595353314f5a393230727838485434304255746c0a553847654c67596c356835463937334b684c6c624969784837514b42675144706e5658665271716f3439512f774b5175395556554a4273436e63364a564c764e0a49314a35426b6e6b69372b68634b6a4743716533503869794b7745313533346f656c506d636c743678354e663543436c634b5065776d4a6f6b516c737a7757750a334b35537262536a4a2f794e58346a6d765643796d497179316257546e4c2f6c2f46396f756a52446938777270786967754b6a4c466f7352744d43586b6a7a4d0a543035614c48337a52774b42675144336f726a6158314c516756666b537164304c4a6d747a625367784f45447774334d6a5633566431483938597569783265480a527461505950726164644a336f4d326c4b41583355504a6863703643536b506b56485133485a664c34635345716a396e786c4146537857336b69694c645957720a7a3559454452506b733834304862464c4d2f58634a6e556c584c2f4b6f685850677763752b4a7459744a5274695772474c774c386535413043514b42675143320a7275754538327a6e4c326f2b42485966706e7431686470395845777a686b687037584a443439414b3465475437465a2b7237786868345a3546546f59486850410a735a424569433754503567576833326b41676154587579336d7075464e4172637141504638634a74534171747677522b63354c555a6f636e76416b4843712f680a75453466786d537959584c6976414e3951346e7a626f69483678496b4e5235494973684271634e415a774b42674376447647673037542b5242456d50647073580a66475979764d72422b396838517342456f636e534b362b61373373764e71424f6b646b746c43724c446873746a344a47523765696a57353639743448507165380a634a674f695547576c56696c4e6661383770476461636832416453324b424452334d396a4f57377455786e417549524e7163675a65456b4b486a4877474379540a4e74362b716d2b4b4b44466d3044366179485157374d432b0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a"

type pkcs1RSAPub struct {
    N *big.Int
    E int
}

// LoadSKIBytes loads a certificate from --cert-hex or --cert-file (or default)
// and returns the SHA-256 SKI bytes computed over the PKCS#1 DER public key.
func LoadSKIBytes(args []string) ([]byte, error) {
    fs := flag.NewFlagSet("cert-flags", flag.ContinueOnError)
    fs.SetOutput(io.Discard) // suppress flag parsing output

    certHex := fs.String("cert-hex", "", "certificate as hex string")
    certFile := fs.String("cert-file", "", "certificate file (DER or PEM)")

    if err := fs.Parse(args); err != nil {
        return nil, err
    }

    if *certHex != "" && *certFile != "" {
        return nil, fmt.Errorf("specify only one of --cert-hex or --cert-file")
    }

    var certBytes []byte
    var err error

    switch {
    case *certHex != "":
        certBytes, err = hex.DecodeString(*certHex)
        if err != nil {
            return nil, fmt.Errorf("invalid cert-hex: %w", err)
        }

    case *certFile != "":
        certBytes, err = os.ReadFile(*certFile)
        if err != nil {
            return nil, fmt.Errorf("cannot read cert file: %w", err)
        }

    default:
        certBytes, err = hex.DecodeString(DefaultCertHex)
        if err != nil {
            return nil, fmt.Errorf("invalid default cert hex: %w", err)
        }
    }

    // Parse the certificate
    cert, err := x509.ParseCertificate(certBytes)
    if err != nil {
        return nil, fmt.Errorf("invalid certificate: %w", err)
    }

    // Extract RSA public key
    rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("certificate is not an RSA public key")
    }

    // Marshal as PKCS#1 DER (modulus + exponent)
    pub := pkcs1RSAPub{
        N: rsaPub.N,
        E: rsaPub.E,
    }
    pkcs1DER, err := asn1.Marshal(pub)
    if err != nil {
        return nil, fmt.Errorf("cannot marshal PKCS#1: %w", err)
    }

    // SHA-256 → SKI
    ski := sha256.Sum256(pkcs1DER)
    return ski[:], nil
}

func LoadCertBytes(args []string) ([]byte, error) {
        fs := flag.NewFlagSet("cert-flags", flag.ContinueOnError)
        fs.SetOutput(io.Discard) // suppress flag.Parse errors output

        certHex  := fs.String("cert-hex",  "", "certificate as hex string")
        certFile := fs.String("cert-file", "", "certificate file (DER or PEM)")

        // Parse ONLY known flags, ignore others
        if err := fs.Parse(args); err != nil {
                return nil, err
        }

        if *certHex != "" && *certFile != "" {
                return nil, fmt.Errorf(
                        "cert: specify only one of --cert-hex or --cert-file",
                )
        }

        switch {
        case *certHex != "":
                return loadHexArg("cert", *certHex)

        case *certFile != "":
                return loadFileArg("cert", *certFile)

        default:
                return loadHexArg("cert (default)", DefaultCertHex)
        }
}

func LoadKeyBytes(args []string) ([]byte, error) {
        fs := flag.NewFlagSet("key-flags", flag.ContinueOnError)
        fs.SetOutput(io.Discard)

        keyHex  := fs.String("key-hex",  "", "private key as hex string")
        keyFile := fs.String("key-file", "", "private key file (DER or PEM)")

        if err := fs.Parse(args); err != nil {
                return nil, err
        }

        if *keyHex != "" && *keyFile != "" {
                return nil, fmt.Errorf(
                        "key: specify only one of --key-hex or --key-file",
                )
        }

        switch {
        case *keyHex != "":
                return loadHexArg("key", *keyHex)

        case *keyFile != "":
                return loadFileArg("key", *keyFile)

        default:
                return loadHexArg("key (default)", DefaultKeyHex)
        }
}

func loadHexArg(name, v string) ([]byte, error) {
        b, err := hex.DecodeString(v)
        if err != nil {
                return nil, fmt.Errorf("%s: invalid hex: %w", name, err)
        }
        return b, nil
}

func loadFileArg(name, path string) ([]byte, error) {
        b, err := os.ReadFile(path)
        if err != nil {
                return nil, fmt.Errorf("%s: cannot read file: %w", name, err)
        }
        return b, nil
}
