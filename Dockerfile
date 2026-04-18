FROM golang:1.22-alpine
WORKDIR /app
COPY go.mod ./
COPY *.go ./
CMD ["go", "test", "-v", "./..."]
