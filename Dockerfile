# syntax=docker/dockerfile:1

FROM golang:alpine
RUN adduser -D -h /app app
USER app
WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /app/nodegraph-provider

EXPOSE 9393

CMD [ "/app/nodegraph-provider", "--config", "config.yaml" ]
