# This image is manually pushed to gcr.io/anthos-networking-ci/toolbox:wora-test
FROM ubuntu:18.04 as builder
RUN apt-get update
RUN apt-get install -y clang git make
RUN git clone https://github.com/google/neper.git
WORKDIR /neper
RUN make

FROM ubuntu:18.04
ENV TERM=xterm
WORKDIR /
RUN apt-get update && apt-get install -y \
	arping \
	bash \
	bc \
	curl \
	dnsutils \
	docker \
	ethtool \
	htop \
	iperf \
	iperf3 \
	iproute2 \
	iputils-ping \
	jq \
	kmod \
	lsof \
	net-tools \
	netcat \
	openssl \
	openssh-server \
	procps \
	sudo \
	sysstat \
	systemd \
	tcpdump \
	tcptraceroute \
	telnet \
	traceroute \
	vim \
	vim-common
COPY --from=builder /neper/tcp_stream .
COPY --from=builder /neper/tcp_rr .
COPY --from=builder /neper/udp_stream .
COPY --from=builder /neper/udp_rr .
COPY --from=builder /neper/tcp_crr .
