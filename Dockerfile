FROM scratch

ARG TARGETARCH

WORKDIR /app
COPY dist/${TARGETARCH}/wireproxy-rs /wireproxy-rs

ENTRYPOINT ["/wireproxy-rs"]
