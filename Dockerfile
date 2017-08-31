FROM centos:7
MAINTAINER      Federico Simoncelli <fsimonce@redhat.com>

RUN yum update -y && \
    yum install -y openscap-scanner git && \
    yum clean all

ENV PATH=$PATH:/usr/local/go/bin
ENV CGO_ENABLED=0

COPY .  /go/src/github.com/openshift/image-inspector

RUN cd /tmp && \
    curl -LO https://storage.googleapis.com/golang/go1.7.linux-amd64.tar.gz && \
    tar -C /usr/local -xvzf go1.7.linux-amd64.tar.gz && \
    rm -f go1.7.linux-amd64.tar.gz && \
    GOBIN=/usr/bin \
    GOPATH=/go \
    go install -tags 'containers_image_openpgp exclude_graphdriver_devicemapper exclude_graphdriver_btrfs' \
    -a -installsuffix cgo \
    /go/src/github.com/openshift/image-inspector/cmd/image-inspector.go && \
    mkdir -p /var/lib/image-inspector

EXPOSE 8080

WORKDIR /var/lib/image-inspector

ENTRYPOINT ["/usr/bin/image-inspector"]
