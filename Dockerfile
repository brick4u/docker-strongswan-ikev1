FROM ubuntu:26.04
LABEL org.opencontainers.image.authors="Andreas Steffen <andreas.steffen@strongswan.org>"
ENV VERSION="6.1.0"
# SHA-256 of the upstream release archive.
ARG STRONGSWAN_SHA256=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4

RUN \
  # install packages
  DEV_PACKAGES="wget bzip2 make gcc libssl-dev pkg-config" && \
  apt-get -y update && \
  apt-get -y install ca-certificates openssl iproute2 iputils-ping nano $DEV_PACKAGES && \
  \
  # download and build strongSwan IKEv1/IKEv2 daemon
  mkdir /strongswan-build && \
  cd /strongswan-build && \
  wget https://download.strongswan.org/strongswan-$VERSION.tar.bz2 && \
  echo "$STRONGSWAN_SHA256  strongswan-$VERSION.tar.bz2" | sha256sum -c - && \
  tar xfj strongswan-$VERSION.tar.bz2 && \
  cd strongswan-$VERSION && \
  ./configure --prefix=/usr --sysconfdir=/etc --disable-defaults      \
    --enable-charon --enable-ikev1 --enable-ikev2 --enable-nonce --enable-random     \
    --enable-openssl --enable-pem --enable-x509 --enable-pubkey       \
    --enable-constraints --enable-pki --enable-socket-default         \
    --enable-kernel-netlink --enable-swanctl --enable-resolve         \
    --enable-eap-identity --enable-eap-md5 --enable-eap-dynamic       \
    --enable-eap-tls --enable-updown --enable-vici --enable-ml        \
    --enable-silent-rules  && \
   make all && make install && \
   install -D -m 0644 COPYING /usr/share/licenses/strongswan/COPYING && \
   cd / && rm -R strongswan-build && \
   ln -s /usr/libexec/ipsec/charon charon && \
   \
   # clean up
   apt-get -y remove $DEV_PACKAGES && \
   apt-get -y autoremove && \
   apt-get clean && \
   rm -rf /var/lib/apt/lists/*

# Expose IKE and NAT-T ports
EXPOSE 500/udp 4500/udp

COPY strongswan.conf /etc/strongswan.conf
LABEL org.opencontainers.image.source="https://github.com/brick4u/docker-strongswan-ikev1"
CMD ["/usr/libexec/ipsec/charon"]
