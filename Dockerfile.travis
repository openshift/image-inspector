FROM travis/image-inspector-base
RUN yum install -y git && \
    yum install -y which && \
    yum install -y make
ENV GOPATH=/go
COPY . /go/src/github.com/openshift/image-inspector
WORKDIR /go/src/github.com/openshift/image-inspector
RUN make install-travis
ENTRYPOINT make
