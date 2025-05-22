FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build .

FROM alpine:3

WORKDIR /app

COPY --from=builder /app/medods-auth .
COPY --from=builder /app/.env .
COPY --from=builder /app/docs ./docs/
COPY --from=builder /app/migrations ./migrations/

EXPOSE 8080

CMD ["./medods-auth"]
