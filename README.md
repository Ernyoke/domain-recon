# domain-recon

## Intro

`domain-recon` is a tool which can be used for reconnaissance. It helps extend the attack surface for in case of a 
certain domain. It fetches all the available active certificates for a host and, using certificate parsing, extracts
all available domains from "Common Name" and "Matching Identities" fields.
Moreover, in a lot of cases it may encounter certificates issued for wildcard domains (example: `*.example.com`). 
For these domains, it can use a word list to extend these wildcards by filling on words from the list and generate
potential subdomains.

### Example of usage:

```shell
domain-recon -d wikipedia.org -f words.txt
```

The output of this will look similar to this:

```shell
wikipedia.org - IPs: [91.198.174.192]
c.ssl.shopify.com - IPs: [23.227.38.74]
store.wikipedia.org - IPs: [91.198.174.192]
m.wikipedia.org - IPs: [91.198.174.192]
zero.wikipedia.org - IPs: [91.198.174.192]

Extended domains:
www.wikipedia.org - IPs: [91.198.174.192]
en.wikipedia.org - IPs: [91.198.174.192]
mail.wikipedia.org - IPs: [91.198.174.192]
test.m.wikipedia.org - IPs: [91.198.174.192]
test.wikipedia.org - IPs: [91.198.174.192]
download.wikipedia.org - IPs: [91.198.174.192]
en.m.wikipedia.org - IPs: [91.198.174.192]
new.m.wikipedia.org - IPs: [91.198.174.192]
new.wikipedia.org - IPs: [91.198.174.192]
my.wikipedia.org - IPs: [91.198.174.192]
stats.wikipedia.org - IPs: [91.198.174.192]
my.m.wikipedia.org - IPs: [91.198.174.192]
shop.wikipedia.org - IPs: [91.198.174.192]
```

## Building the Project

The project requires Go 1.18 or above.

```shell
git clone git@github.com:Ernyoke/domain-recon.git
cd domain-recon
go build
```
