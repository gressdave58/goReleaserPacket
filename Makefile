build:
	echo "Compiling for go"
	@go build -o bin/goreleaserPcap src/goreleaserPcap.go 
run:
	@go run src/goreleaserPcap.go% 
