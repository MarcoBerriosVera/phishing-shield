FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY . .
ENV GOFLAGS=-mod=mod
RUN go build -o heuristics .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/heuristics .
EXPOSE 8081
CMD ["./heuristics"]