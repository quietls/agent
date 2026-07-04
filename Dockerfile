FROM golang:1.26-alpine AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /ssl-agent ./cmd/ssl-agent

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /ssl-agent /usr/local/bin/ssl-agent

ENTRYPOINT ["ssl-agent"]
CMD ["--help"]