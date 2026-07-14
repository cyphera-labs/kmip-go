FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache go-1.22 && rm -rf /var/cache/apk/*
ENV PATH="/usr/lib/go-1.22/bin:$PATH"
USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot go.mod ./
COPY --chown=nonroot:nonroot *.go ./
CMD ["go", "test", "-v", "./..."]
