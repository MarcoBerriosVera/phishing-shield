FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN go build -o vault .

FROM alpine:3.20
WORKDIR /app
RUN mkdir -p /data && chmod 700 /data
COPY --from=builder /app/vault .
EXPOSE 8086
VOLUME ["/data"]
CMD ["./vault"]
