FROM registry.centos.org/centos/centos:7
MAINTAINER      Federico Simoncelli <fsimonce@redhat.com>

# EPEL repo needed for golang on CentOS 7.
RUN yum update -y && \
    yum install -y epel-release && \
    yum install -y golang && \
    yum install -y openscap-scanner && \
    yum install -y git && \
    yum clean all

COPY .  /go/src/github.com/openshift/image-inspector

RUN GOBIN=/usr/bin \
    GOPATH=/go \
    CGO_ENABLED=0 \
    go install -a -installsuffix cgo /go/src/github.com/openshift/image-inspector/cmd/image-inspector.go && \
    mkdir -p /var/lib/image-inspector

EXPOSE 8080

WORKDIR /var/lib/image-inspector

ENTRYPOINT ["/usr/bin/image-inspector"]
