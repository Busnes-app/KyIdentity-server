# Multi-stage build for KyIdentity Server

# Stage 1: Build React Frontend
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Go Binary with Embedded Frontend
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS backend-builder
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
