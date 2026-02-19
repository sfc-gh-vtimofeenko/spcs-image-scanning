FROM --platform=linux/amd64 alpine:3.19
# Production image should use a different approach, not curl | bash and should generally not keep curl around
# This approach is, however, concise
RUN apk add --no-cache curl bash coreutils jq \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Add wrapper script
COPY grype-wrapper /grype-wrapper
RUN chmod +x /grype-wrapper
ENTRYPOINT ["/grype-wrapper"]
