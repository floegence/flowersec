# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine AS build

WORKDIR /src/flowersec-go

COPY flowersec-go/go.mod flowersec-go/go.sum ./
RUN go mod download

COPY flowersec-go ./

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
  go build -trimpath -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
  -o /out/flowersec-tunnel ./cmd/flowersec-tunnel

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/flowersec-tunnel /usr/local/bin/flowersec-tunnel

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/flowersec-tunnel"]
