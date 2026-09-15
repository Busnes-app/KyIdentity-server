# Multi-stage build for KyIdentity Server

# Stage 1: Build React Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Go Binary with Embedded Frontend
FROM golang:1.26-alpine AS backend-builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kyidentity ./cmd/kyidentity

# Stage 3: Minimal Production Image
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S kyidentity && adduser -S kyidentity -G kyidentity \
    && mkdir -p /data /css /fonts \
    && chown -R kyidentity:kyidentity /data /css /fonts

WORKDIR /
COPY --from=backend-builder /kyidentity /usr/local/bin/kyidentity
COPY css/ /css/
COPY fonts/ /fonts/

USER kyidentity:kyidentity
VOLUME ["/data"]
EXPOSE 5867

ENTRYPOINT ["/usr/local/bin/kyidentity"]
