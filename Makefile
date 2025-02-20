all: keygenc testcrypto
	
keygenc: keygen.c
	gcc -o keygenc keygen.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/

testcrypto: test.go ep11/types.go ep11/error.go  ep11/params.go ep11/hsminit.go ep11/ep11.go
	go build -o testcrypto test.go

