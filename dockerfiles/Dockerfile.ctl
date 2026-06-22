FROM golang:1.24-alpine AS builder
RUN go install github.com/az7even/ctl@latest 2>/dev/null || \
    go install github.com/imthaghost/ctl@latest 2>/dev/null || true
# Fallback: use subfinder which supports CTL internally
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/ /usr/local/bin/
RUN mkdir /output
# Use subfinder with ctl source as the CTL entrypoint
ENTRYPOINT ["subfinder", "-s", "crtsh"]
