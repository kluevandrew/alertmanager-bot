FROM golang:1.16.5-alpine3.13 as builder

ADD . /go/src/app
WORKDIR /go/src/app

ENV CGO_ENABLED=1

RUN apk update && apk upgrade && \
    apk add --no-cache gcc && \
    go build ./cmd/alertmanager-bot


FROM alpine:latest
ENV TEMPLATE_PATHS=/templates/default.tmpl
RUN apk add --update ca-certificates tini

COPY ./default.tmpl /templates/default.tmpl
COPY --from=builder /go/src/app/alertmanager-bot /usr/bin/alertmanager-bot

ENTRYPOINT ["/sbin/tini", "--"]

CMD ["/usr/bin/alertmanager-bot"]
