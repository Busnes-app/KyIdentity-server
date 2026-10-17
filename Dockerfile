# Multi-stage build for KyIdentity Server

# Stage 1: Build React Frontend
FROM node:26-alpine@sha256:143494b1da2945f061539253adc65e4f1569ddf07da2d384c022c791a9d90a4a AS frontend-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Go Binary with Embedded Frontend
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS backend-builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kyidentity ./cmd/kyidentity

# Stage 3: Minimal Production Image
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
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
