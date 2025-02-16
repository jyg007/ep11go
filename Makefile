all: keygenc testcrypto
	
keygenc: keygen.c
	gcc -o keygenc keygen.c -l ep11 -I /usr/include/ep11 -I /usr/include/opencryptoki/

testcrypto: test.go types.go error.go  params.go hsminit.go
	go build -o testcrypto types.go error.go test.go params.go hsminit.go

