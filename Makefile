all: keygenc testcrypto aescreatekey createblskeypair blsaggregatepk blsaggregatesig signbls ep11-agg derivekey derivekeybls createseed uncipherblob createkyberkeypair kyberencapsulate kyberdecapsulate aesencrypt aesdecrypt

deps = ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go ep11/constants.go

keygenc: keygen.c
	gcc -o keygenc keygen.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/
ep11-agg: ep11-agg.c
	gcc -o ep11-agg ep11-agg.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/

testcrypto: test.go ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go ep11/constants.go
	go build -o testcrypto test.go

aescreatekey: aescreatekey.go
	go build $^

aesencrypt: aesencrypt.go
	go build $^

aesdecrypt: aesdecrypt.go
	go build $^

createblskeypair: createblskeypair.go
	go build $^

createkyberkeypair: createkyberkeypair.go
	go build $^

blsaggregatepk: blsaggregatepk.go $(deps)
	go build blsaggregatepk.go
blsaggregatesig: blsaggregatesig.go $(deps)
	go build blsaggregatesig.go
signbls: signbls.go $(deps)
	go build  signbls.go
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
