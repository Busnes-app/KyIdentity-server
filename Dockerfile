# Multi-stage build for KyIdentity Server

# Compile the browser PQ helper from the same pinned module and Go toolchain.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS pq-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
RUN mkdir -p web/.pq && GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -o web/.pq/pq.wasm github.com/Busnes-app/ky-primitives/cmd/pqwasm \
    && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/.pq/wasm_exec.js \
    && cp "$(go list -m -f '{{.Dir}}' github.com/Busnes-app/ky-primitives)/xwing/testdata/vectors.json" web/.pq/vectors.json

# Stage 1: Build React Frontend
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# TypeScript checks the cross-language fixture imported by the frontend tests too.
COPY internal/api/testdata/keyring_xwing.json /app/internal/api/testdata/keyring_xwing.json
COPY --from=pq-builder /app/web/.pq ./.pq
RUN node src/ky-ui/check-vendor.mjs && npx tsc -b && npx vite build

# Stage 2: Build Go Binary with Embedded Frontend
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS backend-builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/web/dist ./web/dist
# Release builds pass the tag's version (X.Y.Z or X.Y.Z.N); other builds report internal/appversion/VERSION.
# -trimpath keeps the build directory out of the binary, so the same commit, Go version and
# VERSION give the same bytes wherever it is built (docs/VERIFYING-RELEASES.md).
ARG VERSION=
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/Busnes-app/kyidentity-server/internal/appversion.release=${VERSION}" \
    -o /kyidentity ./cmd/kyidentity

# Stage 3: Minimal Production Image
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
