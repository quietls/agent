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

# docker-cli lets the agent reload a sibling web-server container via the
# mounted docker socket (SSL_AGENT_RELOAD_COMMAND="docker exec <nginx> nginx -s reload")
# in sidecar deployments where the agent has no local nginx binary.
RUN apk add --no-cache ca-certificates docker-cli

COPY --from=builder /ssl-agent /usr/local/bin/ssl-agent

ENTRYPOINT ["ssl-agent"]
CMD ["daemon"]