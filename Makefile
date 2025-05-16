all: testcrypto aescreatekey createblskeypair blsaggregatepk blsaggregatesig signbls derivekey derivekeybls createseed uncipherblob createkyberkeypair kyberencapsulate kyberdecapsulate aesencrypt aesdecrypt createdilithkeypair signdilith verifydilith aescreatekeysession verifybls reencipher reencipher2 getmech aesreencrypt eccreatekeypair ecdh kyberencapsulatehybrid kyberdecapsulatehybrid benchmark4 readattr

deps = ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go ep11/constants.go

keygenc: keygen.c
	gcc -o keygenc keygen.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/
ep11-agg: ep11-agg.c
	gcc -o ep11-agg ep11-agg.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/

testcrypto: test.go ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go ep11/constants.go
	go build -o testcrypto test.go

aescreatekey: aescreatekey.go
	go build $^

reencipher: reencipher.go
	go build $^

reencipher2: reencipher2.go
	go build $^

getmech: getmech.go
	go build $^

eccreatekeypair: eccreatekeypair.go
	go build $^

ecdh: ecdh.go
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
