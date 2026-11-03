# strongSwan with IKEv1 and IKEv2

Container image: `ghcr.io/brick4u/strongswan-ikev1`

Ubuntu 26.04 with strongSwan 6.1.0, built from the SHA-256-pinned upstream release. IKEv1 and IKEv2 are explicitly enabled, with `swanctl` configuration and the VICI control interface. The default command runs `/usr/libexec/ipsec/charon` in the foreground. The standard `charon.start-scripts` configuration runs `swanctl --load-all` when charon starts.

## Run

Prepare your connection definitions and credentials in a local `swanctl/` directory, following the [swanctl configuration reference](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html). Set `version = 1` for IKEv1 or `version = 2` for IKEv2 in each connection.

```sh
docker run -d --name strongswan \
  --read-only --cap-drop ALL \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-add NET_BIND_SERVICE \
  -p 500:500/udp -p 4500:4500/udp \
  --mount type=bind,src="$(pwd)/swanctl",dst=/etc/swanctl,readonly \
  --tmpfs /run \
  ghcr.io/brick4u/strongswan-ikev1:6.1.0

docker exec strongswan swanctl --list-sas
```

The integration tests pass with exactly these three capabilities and a read-only root filesystem. The host kernel must support XFRM/IPsec. Configure routing, forwarding and firewall rules for the protected traffic. UDP 500 and 4500 must reach the container.

Mounted files must be readable by the container's UID 0. Kubernetes Secret volumes can use root-owned mode `0400`; set suitable ownership and permissions for local bind mounts.

`/etc/swanctl` holds configuration and credentials. `/run` is charon's writable runtime directory and contains the VICI socket. Share this runtime directory with authorized VICI clients through a Pod-local volume. Protect credentials on the host and restrict access to the Docker daemon and VICI interface.

## Builds and tests

The GitHub Actions workflow builds an amd64 test image and runs:

```sh
python3 tests/integration.py --execute --image strongswan-ikev1:test
```

The integration harness tests IKEv1 and IKEv2 with PSK authentication, AES-256/SHA-256/ECP-384, NAT-T on UDP/4500, protected traffic in both directions, CHILD_SA rekeying and IKE reauthentication. It also checks default startup and automatic configuration loading. Failures produce sanitized diagnostics in the job log and summary.

Pushes to `master`, pull requests, manual runs and the weekly schedule trigger CI. After successful tests, runs on `master` publish amd64 and arm64 images to GHCR. Pull requests only build and test. Published tags are `master` and the upstream version from the Dockerfile, currently `6.1.0`.

Weekly rebuilds pull the Ubuntu base and refresh its package updates. Both tags are mutable; pin an image digest for reproducible deployments. OCI labels record the source repository, Git revision and upstream version.

## Source and licensing

This project derives from the [`strongswan` directory in strongX509/docker](https://github.com/strongX509/docker/tree/71b4a2de6b68a14f32c69505b84268b45acafdf1/strongswan), at commit `71b4a2de6b68a14f32c69505b84268b45acafdf1`. The packaging changes enable IKEv1 alongside IKEv2, verify the release archive with SHA-256, add foreground startup and automatic swanctl loading, and provide tested multi-platform publishing.

strongSwan is distributed under GPLv2; see [COPYING](COPYING) and the [upstream release source](https://download.strongswan.org/strongswan-6.1.0.tar.bz2). The image includes the license at `/usr/share/licenses/strongswan/COPYING`.
