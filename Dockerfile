FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod *.go deploy_node.py ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /linode-node-manager .
FROM alpine:3.20
RUN apk add --no-cache ca-certificates openssh-client bash python3
COPY --from=build /linode-node-manager /usr/local/bin/linode-node-manager
RUN mkdir -p /data /run/secrets
EXPOSE 8000
CMD ["/usr/local/bin/linode-node-manager"]
