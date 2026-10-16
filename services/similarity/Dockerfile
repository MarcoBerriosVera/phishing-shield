FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY . .
ENV GOFLAGS=-mod=mod
RUN go build -o similarity .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/similarity .
EXPOSE 8082
CMD ["./similarity"]