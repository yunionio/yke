all: bin

bin: clean
	go build -o bin/yke ./main.go

clean:
	rm -rf bin
