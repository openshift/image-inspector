FROM registry.centos.org/centos/centos:7
MAINTAINER      Federico Simoncelli <fsimonce@redhat.com>

RUN yum update -y && \
    yum install -y golang openscap-scanner git && \
    yum clean all

COPY .  /go/src/github.com/openshift/image-inspector

RUN export GOBIN=/usr/bin && \
    export GOPATH=/go && \
    export CGO_ENABLED=0 && \
    cd /go/src/github.com/openshift/image-inspector && \
    go get -v github.com/golang/dep/cmd/dep && \
    dep ensure -vendor-only -v && \
    go install -a -installsuffix cgo cmd/image-inspector.go && \
    mkdir -p /var/lib/image-inspector

EXPOSE 8080

WORKDIR /var/lib/image-inspector

ENTRYPOINT ["/usr/bin/image-inspector"]
