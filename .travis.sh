#!/usr/bin/env bash

function build_container(){
    docker build -t travis/image-inspector-base .
    cat > Dockerfile.travis <<EOF
FROM travis/image-inspector-base
RUN yum install -y \
    git \
    which \
    make
RUN yum remove -y golang
RUN curl -O https://storage.googleapis.com/golang/go1.8.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.8.3.linux-amd64.tar.gz && \
    rm -f  go1.8.3.linux-amd64.tar.gz
ENV PATH=${PATH}:/usr/local/go/bin
ENV GOPATH=/go
COPY . /go/src/github.com/openshift/image-inspector
WORKDIR /go/src/github.com/openshift/image-inspector
RUN make install-travis
ENTRYPOINT make
EOF
    docker build -t travis/image-inspector -f Dockerfile.travis .
}

function run_tests(){
  docker run --rm --privileged \
          -v /var/run/docker.sock:/var/run/docker.sock \
          --entrypoint make \
          travis/image-inspector verify test-unit
}

function usage() {
    echo "usage: .travis.sh build|run"
    exit 1
}

case "$1" in
    build)
        build_container
        ;;
    run)
        run_tests
        ;;
    *)
        usage
        ;;
esac
