---
title: "6 Things to Do With Docker"
date: 2024-03-12T13:24:47+02:00
---
## 1. Operate on root files without sudo password

We all know that docker access __is basically root access__, but examples are critical to understanding. 

{{< highlight bash >}}
$ cat /etc/shadow
cat: /etc/shadow: Permission denied

$ docker run --mount type=bind,source="/etc/",target="/etc-host" \
    --rm --name nosudo -it ubuntu bash -c "cat /etc-host/shadow"
root:!:***********************:::
daemon:***********************:::
bin:*:************************:::
    
{{< / highlight >}}

## 2. Operate on docker itself

This is like docker inside docker (dind), but it doesn't require any privileged permissions, but given the example above, you know...

{{< highlight bash >}}
docker run --rm --name nosudo \
    --mount type=bind,source="/var/run",target="/var-host-run" \
    -it ubuntu bash \
    -c "apt update && apt install -y curl && curl --unix-socket /var-host-run/docker.sock http://localhost/v1.44/containers/json"
{{< / highlight >}}

## 3. Block specific system calls using seccomp filters

A `seccomp` filter is the Linux foundation for all the sandboxes running under Linux, it's possible to do it on your own. 

You download a default seccomp filter from somewhere, like [this](https://raw.githubusercontent.com/docker/labs/master/security/seccomp/seccomp-profiles/default.json), 
then modify the list accordingly. 

Say you don't want `connect()` syscalls

{{< highlight json >}}
{
    "name": "connect",
    "action": "SCMP_ACT_ALLOW",
    "args": []
}
{{< / highlight >}}

Modify to 

{{< highlight json >}}
{
    "name": "connect",
    "action": "SCMP_ACT_ERRNO",
    "args": []
}
{{< / highlight >}}

And now if you do this: (adding `--security-opts seccomp=profile.json`) 

{{< highlight bash >}}
docker run --rm --name nosudo \
    --security-opt seccomp=profile.json --mount \
    type=bind,source="/var/run",target="/var-host-run" -it ubuntu bash \
    -c "apt update && apt install -y curl && curl --unix-socket /var-host-run/docker.sock http://localhost/v1.44/containers/json"
{{< / highlight >}}

The container cannot download anything due to `connect()` syscall blocked. 

What you'd want now is some sort of an allow list or a deny list in the `sockaddr*` argument of `connect()`, but this is not possible due to seccomp limitations. 

## 4. Have specific allow list of hosts on the container

Now this seems rather stupid but it should work quite well - use the DNS mechanism of the container + a simple DNS server container with predefined list of hosts. 

Say build downloads stuff from `NPM`, provide the allowed domains to it, but prevent any other from getting actual IP (route to localhost). 

On itself it's quite idiotic but it can stop various 3rd party exfiltrations of your data. 

Now let's use `dnsmasq` 

Relevant Dockerfile: 
{{< highlight Dockerfile >}}
FROM alpine
RUN apk add --no-cache dnsmasq
COPY dnsmasq.conf /etc/dnsmasq.conf
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["dnsmasq", "-k", "--conf-file=/etc/dnsmasq.conf", "-log-queries", "--no-daemon"]
{{< / highlight >}}
_The -log-queries and -no-daemon are for debugging, you can drop it later_

Relevant `dnsmasq.conf` file
{{< highlight ini>}}
address=/#/127.0.0.1
{{< / highlight >}}

Now this seems so silly, the configuration is empty... 

Well `dnsmasq` uses `/etc/hosts` file and **we control it from `--add-host` argument of `docker run`** 

What we get is something super funny which looks something like (`dns` is the `docker build -t dns .` execution of the above)
{{< highlight bash >}}
docker run --add-host="wagon.cool:17.17.17.17" --cap-add=NET_ADMIN -p 8053:53/udp -it dns
{{< / highlight >}}

(You'd need to find the container IP with `docker inspect`)

{{< highlight bash >}}
$ dig @172.17.0.2 wagon.cool

;; ANSWER SECTION:
wagon.cool.		0	IN	A	17.17.17.17

$ dig @172.17.0.2 wagon.not.cool

;; ANSWER SECTION:
wagon.not.cool.		0	IN	A	127.0.0.1

{{< / highlight >}}

A bit of playing with each container you have and you'd get a reasonable list which isn't very long of what you can approve. 
This is a very good trick to control the build flow directly from bash itself, which isn't very visible with other external (and sometimes **expensive!**) tools. 

I thought this is a good solution as you don't have wildcards in /etc/hosts, otherwise you just wildcard all to `127.0.0.1` and known hosts to their IP.

Control the relevant container with:
{{< highlight bash >}}
docker run --dns=172.17.0.2 -it ubuntu
{{< / highlight >}}


## 5. A container is tar file, and tar files are polyglots...

A `tar` file is file format which has enough space to actually be a an `ELF` file [ISO+TAR+ELF](https://sysfatal.github.io/polyglottar-en.html). 

A `tar` file is also the image you download from a `docker` repository. 

{{< highlight bash >}}
$ docker save ubuntu > what_is.it
$ file what_is.it 
what_is.it: POSIX tar archive
{{< / highlight >}}

Now you can pretty much combine both, as there is no cryptographic protection on the `manifest` of the container [see spec](https://github.com/opencontainers/image-spec/blob/main/spec.md)

It is doable to have a tiny loader embedded inside a container to ship applications directly as a container. 

Didn't check if the `docker repository` allows pushing such thing. I hope it doesn't. 

## 6. Download arbitrary data from OUTSIDE! while pulling a container

I hope this doesn't work, but it seems to be only `depreacted` and `frowned upon` on the [spec](https://github.com/opencontainers/image-spec/blob/main/layer.md#non-distributable-layers). 

I didn't bother checking, but the `urls` field on the layer itself seems well defined, I guess you only need a vaild hash for the file you download. 

You can create some sort of a "1pt pixel" trick for emails, but for containers. 

I really hope this doesn't work.



