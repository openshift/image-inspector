FROM openshift/origin-base
MAINTAINER Federico Simoncelli <fsimonce@redhat.com>

RUN yum install -y golang openscap-scanner && yum clean all

ENV PKGPATH=/go/src/github.com/openshift/image-inspector

WORKDIR $PKGPATH

ADD .   $PKGPATH
ENV GOBIN  /usr/bin
ENV GOPATH /go:$PKGPATH/Godeps/_workspace

RUN go install $PKGPATH/cmd/image-inspector.go && \
    mkdir -p /var/lib/image-inspector

EXPOSE 8080

WORKDIR /var/lib/image-inspector

RUN mkdir cve_feeds && \
    wget --no-verbose -P cve_feeds/ \
    https://www.redhat.com/security/data/metrics/ds/com.redhat.rhsa-RHEL{5,6,7}.ds.xml.bz2

ENTRYPOINT ["/usr/bin/image-inspector"]
