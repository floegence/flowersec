# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY --from=build /out/flowersec-runtime /usr/local/bin/flowersec-runtime
COPY LICENSE /usr/share/doc/flowersec/LICENSE
COPY release-compliance/runtime-image/THIRD_PARTY_NOTICES.md /usr/share/doc/flowersec/THIRD_PARTY_NOTICES.md
COPY release-compliance/runtime-image/SBOM_SCOPE.md /usr/share/doc/flowersec/SBOM_SCOPE.md
COPY release-compliance/runtime-image/sbom /usr/share/doc/flowersec/sbom
EXPOSE 8080 443/udp
ENTRYPOINT ["/usr/local/bin/flowersec-runtime"]
