# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

ENV GOTOOLCHAIN=local

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /src
COPY flowersec-go/go.mod flowersec-go/go.sum ./
RUN go mod download
COPY flowersec-go/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
  go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
  -o /out/flowersec-runtime ./cmd/flowersec-runtime

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=build /out/flowersec-runtime /usr/local/bin/flowersec-runtime
COPY LICENSE /usr/share/doc/flowersec/LICENSE
COPY release-compliance/runtime-image/THIRD_PARTY_NOTICES.md /usr/share/doc/flowersec/THIRD_PARTY_NOTICES.md
COPY release-compliance/runtime-image/SBOM_SCOPE.md /usr/share/doc/flowersec/SBOM_SCOPE.md
COPY release-compliance/runtime-image/sbom /usr/share/doc/flowersec/sbom
EXPOSE 8080 443/udp
ENTRYPOINT ["/usr/local/bin/flowersec-runtime"]
