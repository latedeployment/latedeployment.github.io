---
title: "Certificate Transparency Info Leaks"
date: 2026-01-19
tags: ["security", "certificate transparency", "information leak", "kubernetes"]
---

_This is part two of the Certificate Transparency series_.

I show here how certificate transparency is leaking valuable information about companies due to either unfamiliarity or obliviousness from companies' IT or Devops teams. 

# Overview

As we explained in [part one Certificate Transparency 101](/posts/certificate-transparency-101/), certificate transparency makes the details of all trusted SSL certificates public for anyone to see. While it's useful for browsers to validate information about certificates issued by a CA or for a specific domain, it is also useful for attackers to gain valuable information about companies infrastructure. 

*While I cannot show proofs, let's just say that most of the cyber startups I've checked are leaking their entire infrastructure info through certificate transparency. Check for yourself.*

# How subdomains are created

Company buys its domain, let's say `example.com`. They serve it through HTTPs so they'd have to obtain a certificate. Before _Let's Encrypt_ companies would have to pay money to buy a certificate for a year. It wasn't very expensive, but enough to reduce the amount of certificates a company issues. When the company grows, to simplify its internal Infrastructure layout, it usually uses subdomains to separate internal servers from user interface and we'd start seeing `app.example.com`, `login.example.com` and others.

_Let's Encrypt_ allows generating free certificates, as long as the issuer can prove it controls the domain requesting the certificate. To do this, when requesting a certificate for `newcert.example.com`, _Let's Encrypt_ presents a challenge to that specific domain, and the server must respond appropriately to prove control. For more details on challenge methods, see [Let's Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/).

As the company grows, the Devops teams will probably request more control over the subdomains it manages, so if for instance a service for logs storage is developed in the company the `logs.example.com` subdomain will be created. 

After a while, the company will have the example following subdomains: 

- `example.com` - main website
- `login.example.com` - authentication methods, the auth servers are here
- `app.example.com` - the UI after login is here
- `logs.example.com` - the user uploads logs to this website


As the company grows further it might have multiple UIs for various customers and it installs a wildcard certificate, so a `*.console.example.com` will serve both `customerA.console.example.com` and `customerB.console.example.com`. This cannot be done with _Let's Encrypt_, so the company has to buy a certificate from a company selling *wildcard certificates*. As it's expensive, the DevOps team will choose to use _Let's Encrypt_ and will issue a specific certificate per customer.

So now the company have the following subdomains: 

- `example.com` - main website
- `login.example.com` - authentication methods, the auth servers are here
- `app.example.com` - the UI after login is here
- `logs.example.com` - the user uploads logs to this website
- `customerA.console.example.com` - customer A UI
- `customerB.console.example.com` - customer B UI

# Kubernetes

As the company grows (or god forbid from its beginning...) it will start using Kubernetes as it makes spinning up new services trivially easy, and each service will have its own internal subdomain. 

Internally, teams will push to have their own deployment area, like `staging` or `dev`, and this is a very easy thing to do in K8s. So `staging.api.example.com` or `staging.app.example.com` will be created. 

Once companies start using tools like [`cert-manager`](https://cert-manager.io/), the entire certificate and subdomains flow creation is automated, and there is almost nothing to be done by humans. 


# DNS information

As long as the subdomains are only in `DNS`, to gain information about a company you'd have to use brute-force with word-list in order to find something. So you'd have to query `app.example.com` or `ui.example.com` the DNS server to understand what is found and what not in a given company.


# The leak
As described in [part one Certificate Transparency 101](/posts/certificate-transparency-101/), each certificate issued for a domain will be stored *forever* in the certificate transparency logs.

Indeed `app.example.com` doesn't mean anything as a leak, but what about `sailpoint.example.com`, or `okta.example.com`? This is valuable information about whether the company uses or integrates with SailPoint or Okta. 

Due to DevOps teams unfamiliarity with the concept of public logging of the certificates, a vast number of companies leak *their entire infrastructure information* freely, due to the use of `k8s` + `cert-manager` + _Let's Encrypt_. 

When I contacted _Let's Encrypt_, they basically told me people should be aware of this and it's their problem. 

With the help of a website called [crt.sh](https://crt.sh), anyone can query any domain they want, and the website will dump the company's entire infra. The reconnaissance step of understanding how a company works is done in a single search. 

# Summary with LLM

To make everything worse LLM are used everywhere right now. Query the `crt.sh`, cut the domain name to just keep a list of subdomains and tell LLM to summarize the company infrastructure with something like: 

```
  You are a cybersecurity and infrastructure analyst.
  Analyze the provided list of subdomains and generate a concise summary of the company's infrastructure.
  Identify patterns such as:
  - Cloud providers (aws, azure, gcp, cloudflare, etc.)
  - Development/staging/production environments
  - Services and technologies (api, mail, vpn, jenkins, gitlab, etc.)
  - Geographic regions
  - Third-party integrations
  - Security-related services
  - Customer Names?

  Provide a structured summary with bullet points.
```

This provides a summary which pretty much describes the entire company infra, names of their customers and the tools they use. 

# Summary of stuff which is leaked

- Cloud Providers
- Environment types and all servers
- Internal Tools 
- External Integrations
- Customer Names

Your new integration for version _3.0_ with that huge company? Leaked. 

Your highly confidential customer name? Leaked.

Your auth servers? Leaked.

Your monitoring tools? Leaked. 

This is valuable information which shouldn't be visible to the external world. 








