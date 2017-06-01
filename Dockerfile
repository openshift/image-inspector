FROM openshift/origin-base
MAINTAINER Federico Simoncelli <fsimonce@redhat.com>

RUN yum install -y make golang openscap-scanner && yum clean all

ENV PKGPATH=/go/src/github.com/openshift/image-inspector

WORKDIR $PKGPATH

ADD .   $PKGPATH
ENV GOBIN  /usr/bin
ENV GOPATH /go

RUN cd $PKGPATH && \
        make deps && \
        go install $PKGPATH/cmd/image-inspector.go && \
        rm -rf ~/.trash-cache && \
        mkdir -p /var/lib/image-inspector

EXPOSE 8080

WORKDIR /var/lib/image-inspector

ENTRYPOINT ["/usr/bin/image-inspector"]
