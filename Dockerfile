ARG SINGBOX_VERSION=1.11.4
FROM ghcr.io/sagernet/sing-box:v${SINGBOX_VERSION} AS singbox

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /balancer .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=build /balancer /usr/local/bin/balancer
ENTRYPOINT ["balancer", "-c", "/etc/balancer/config.yaml"]
CMD ["run"]
