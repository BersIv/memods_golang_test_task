FROM golang:alpine AS build-env

ENV GOPATH=/
WORKDIR /go/src
COPY . /go/src/
RUN cd /go/src
RUN go mod download
RUN go build -o medods-task ./cmd

FROM alpine

WORKDIR /app
COPY ./cmd/.env /app
COPY --from=build-env /go/src/ /app

CMD ["./medods-task"]
