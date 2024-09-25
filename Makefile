version := $(shell git rev-parse HEAD)
build_date := $(shell TZ="UTC" date '+%F_%H:%M:%S')

all:
	CGO_ENABLED=0 go build -ldflags="-X main.Version=${version} -X main.BuildDate=${build_date}"
clean:
	rm ec2go


