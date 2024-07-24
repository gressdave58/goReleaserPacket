FROM golang:1.21

RUN mkdir -p /opt/goReleaserPacket

WORKDIR /opt/goReleaserPacket

COPY . ./

RUN go mod download && go mod verify
RUN go build -ldflags="-w -s" -v -o /goreleaserPcap goreleaserPcap.go

FROM debian:bookworm-slim

WORKDIR /work

COPY --from=0 /goreleaserPcap /usr/local/bin/goreleaserPcap

COPY docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
