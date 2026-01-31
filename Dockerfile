# Stage 1: Build
FROM golang:1.24 AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -o manager cmd/manager/main.go

# Stage 2: Runtime
FROM ubuntu:24.04

# Install tcpdump and util-linux (for nsenter)
RUN apt-get update && apt-get install -y tcpdump util-linux && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /workspace/manager .

ENTRYPOINT ["/manager"]
