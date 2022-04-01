# syntax=docker/dockerfile:1

FROM golang:alpine
WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /nodegraph-provider

EXPOSE 9393

CMD [ "/nodegraph-provider", "--config", "config.yaml" ]
