# docker-kubernetes-security-101

## Agenda

1. Kubernetes misconfiguration attacks
2. Docker attacks, if any
3. Attack surface in comparision to monolithic applications
4. Docker security tips
5. Tools for hardening docker
6. How to secure it? Dockerfile
7. Hardening dockerfiles
8. Resources to Kubernetes tips
9. 

## Rough outline

### Sample attacks & hacks across the globe

### Live session on how it's done

shodan.io

You can get the pro account for $5 for life time & it's worth it.

Query - port:4040 country:"IN" city:"Mumbai"

You can use their developer guide to write scripts to scrape the data, etc.

https://github.com/JavierOlmedo/shodan-filters

https://github.com/weaveworks/scope

scope launch -app.http.address 0.0.0.0:4040

apk add docker
apk add libcap
capsh --print

https://crontab.guru/

nsenter to create namespaces in linux, 

### Container?

https://github.com/rewanthtammana/containers-from-scratch/blob/master/main.go#L32

### What does it mean to be root inside a container?

It's just an isolation within your same system. 

```bash
adduser nonroot
sudo groupadd docker
sudo usermod -aG docker nonroot
```

```bash
docker run --rm -it -v /:/abcd ubuntu bash
touch /abcd/etc/dockeruser
```

```bash
podman run --rm -it -v /:/abcd ubuntu bash
touch /abcd/etc/podmanuser
```

### Privileged container

Checkf

### Capablities


## Notes

Demo of how security hacks are done!
shodan + script (hide) + enumeration + recon + live hacking (scope)

docker-socket recon

https://github.com/search?q=%2Fvar%2Frun%2Fdocker.sock+filename%3Adocker-compose.yml+language%3AYAML+language%3AYAML&type=Code&ref=advsearch&l=YAML&l=YAML

One of the results -> https://github.com/domwood/kiwi-kafka/blob/f47f91f5611f2c18694764d812d110b62126c694/scripts/docker-compose-kiwi.yml

docker-compose up


### Network Policies

https://github.com/ahmetb/kubernetes-network-policy-recipes

Show your presentation on compromising organizational security bug!



