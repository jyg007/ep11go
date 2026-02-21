all: testcrypto aescreatekey createblskeypair blsaggregatepk blsaggregatesig signbls derivekey derivekeybls createseed uncipherblob createkyberkeypair kyberencapsulate kyberdecapsulate aesencrypt aesdecrypt createdilithkeypair signdilith verifydilith aescreatekeysession verifybls reencipher reencipher2 getmech aesreencrypt eccreatekeypair ecdh kyberencapsulatehybrid kyberdecapsulatehybrid benchmark4 readattr kmsapi rsacreatekeypair ecwrap ecunwrap sessionunwrap sessionwrap spkiunwrap readpubblob readprivblob rsaunwrap aesunwrap ecunwrap2 pkfixasn1 getpubfromskblob ep11login ep11admin ep11load ep11zeroify ep11scanmkvp ep11loadrandom ep11mload ep11audit  ep11card

deps = ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go ep11/constants.go ep11/ep11login.go 

keygenc: keygen.c
	gcc -o keygenc keygen.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/
ep11-agg: ep11-agg.c
	gcc -o ep11-agg ep11-agg.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/

testcrypto: test.go ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go ep11/constants.go
	go build -o testcrypto test.go

aescreatekey: aescreatekey.go
	go build $^

kmsapi: kmsapi.go
	go build $^

reencipher: reencipher.go
	go build $^

pkfixasn1: pkfixasn1.go
	go build $^

reencipher2: reencipher2.go
	go build $^

getmech: getmech.go
	go build $^

eccreatekeypair: eccreatekeypair.go
	go build $^

rsacreatekeypair: rsacreatekeypair.go
	go build $^

getpubfromskblob: getpubfromskblob.go
	go build $^

rsaunwrap: rsaunwrap.go
	go build $^

aesunwrap: aesunwrap.go
	go build $^

ecdh: ecdh.go
	go build $^

spkiunwrap: spkiunwrap.go
	go build $^

readpubblob: readpubblob.go
	go build $^

readprivblob: readprivblob.go
	go build $^

readattr: readattr.go
	go build $^
aescreatekeysession: aescreatekeysession.go
	go build $^

aesencrypt: aesencrypt.go
	go build $^

aesdecrypt: aesdecrypt.go
	go build $^

aesreencrypt: aesreencrypt.go
	go build $^

createblskeypair: createblskeypair.go
	go build $^

createkyberkeypair: createkyberkeypair.go
	go build $^

createdilithkeypair: createdilithkeypair.go
	go build $^

sessionwrap: sessionwrap.go
	go build $^

sessionunwrap: sessionunwrap.go
	go build $^

ecwrap: ecwrap.go
	go build $^

ecunwrap: ecunwrap.go
	go build $^

ecunwrap2: ecunwrap2.go
	go build $^

blsaggregatepk: blsaggregatepk.go $(deps)
	go build blsaggregatepk.go

blsaggregatesig: blsaggregatesig.go $(deps)
	go build blsaggregatesig.go

signbls: signbls.go $(deps)
	go build  signbls.go

signdilith: signdilith.go $(deps)
	go build  signdilith.go

verifydilith: verifydilith.go $(deps)
	go build verifydilith.go

verifybls: verifybls.go $(deps)
	go build verifybls.go

derivekey: derivekey.go $(deps)
	go build  derivekey.go

derivekeybls: derivekeybls.go $(deps)
	go build  derivekeybls.go

createseed: createseed.go $(deps)
	go build  createseed.go

uncipherblob: uncipherblob.go $(deps)
	go build  uncipherblob.go

kyberencapsulate: kyberencapsulate.go $(deps)
	go build  kyberencapsulate.go

kyberdecapsulate: kyberdecapsulate.go $(deps)
	go build  kyberdecapsulate.go

kyberencapsulatehybrid: kyberencapsulatehybrid.go $(deps)
	go build  kyberencapsulatehybrid.go

kyberdecapsulatehybrid: kyberdecapsulatehybrid.go $(deps)
	go build  kyberdecapsulatehybrid.go

benchmark4: benchmark4.go $(deps)
	go build  benchmark4.go

ep11login: ep11login.go $(deps)
	go build  ep11login.go

ep11admin: ep11admin.go $(deps)
	go build  ep11admin.go

ep11load: ep11load.go $(deps)
	go build  ep11load.go

ep11mload: ep11mload.go $(deps)
	go build  ep11mload.go

ep11loadrandom: ep11loadrandom.go $(deps)
	go build  ep11loadrandom.go

ep11zeroify: ep11zeroify.go $(deps)
	go build  ep11zeroify.go

ep11scanmkvp: ep11scanmkvp.go $(deps)
	go build  ep11scanmkvp.go

ep11audit: ep11audit.go $(deps)
	go build  ep11audit.go

ep11card: ep11card.go $(deps)
	go build  ep11card.go
