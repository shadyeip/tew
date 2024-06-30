# tew
`tew` is a simple, quick 'n' dirty nmap parser for converting nmap xml output files to IP:Port notation.

For example:

```
tew -x data/ex1/nmap.xml

1.1.1.1:80
1.1.1.1.1:443
```

This is useful for internal penetration tests and can be piped to httpx easily. As it is go, it compiles into a neat and tidy binary! 

![Example](screenshots/example.jpeg?raw=true "Example of Tew")

# Installation

## Go install
```
go install github.com/pry0cc/tew@latest
```

## Binaries
Binaries are available for most platforms and archectectures in the [releases page](https://github.com/pry0cc/tew/releases/latest).

# Usage
```
# Run Nmap and save to XML output

nmap -T4 1.1.1.1 8.8.8.8 -oX file.xml

tew -x file.xml
tew -x file.xml -o output.txt
tew -x file.xml | httpx -json -o http.json
```

## Stdin support
```
cat data/ex1/nmap.xml | go run main.go -x -
```

93.184.216.34:80
93.184.216.34:443
1.1.1.1:80
8.8.8.8:53
8.8.8.8:443
8.8.4.4:53
8.8.4.4:443
1.0.0.1:53
1.1.1.1:53
1.1.1.1:443
1.0.0.1:80
1.0.0.1:443

## DNSx Parsing
If you want to correlate DNSx JSON output, simply generate a JSON file and import it using the following syntax.
```
subfinder -d domain.com -o subs.txt
dnsx -l subs.txt -json -o dns.json
cat dns.json | jq -r '.a[]' | tee ips.txt
nmap -T4 -iL ips.txt -oX nmap.xml

tew -x nmap.xml -dnsx dns.json --vhost | cut -d : -f1| sort | uniq | httpx -json -o http.json
```

## Include Orphaned IPs
In some situations, your Nmap XML file may contain additional IP addresses that are not present in your DNS JSON file. These IPs do not have associated subdomains in the dns.json file. If you want to include these IP entries in your output, you can use the `--include-orphaned-ips` flag.

This is useful when you have a comprehensive Nmap scan that identifies more IPs than those resolved by DNS lookups. The `--include-orphaned-ips` flag ensures that all relevant IP pairs are included, even if they do not map to any subdomain.

Example output:

```
tew -x nmap.xml -dnsx dns.json --vhost --include-orphaned-ips 

192.168.5.34:80
192.168.5.34:443
sub1.scanme.nmap.org:443
sub1.scanme.nmap.org:80
```

### httpx:
```
tew -x nmap.xml -dnsx dns.json --vhost --include-orphaned-ips | cut -d : -f1| sort | uniq | httpx -json -o http.json
```

## URL Generation
If you want to passively generate URLs, you can do so with the `--urls` option.

Note: This does not replace using httpx, prefer for occasions where stealth matters over accuracy. This does not check to see if the port is running a HTTP service nor does it send any requests.

```
tew -x nmap.xml -dnsx dns.json --vhost --urls 

http://example.com
https://example.com
```

# Todo
- [x] Create auto build using github ci & autobuild
- [x] Add Arm64 for Darwin to Build
- [x] Use proper flags library
- [x] Add ability to import and use dnsx JSON & text output files - working on it!
- [x] Clean up DNSX Parsing module and sort unique
- [x] Add output text file as option
- [x] Test on Windows, Linux & Mac for cross-compatibility

# Credit
- @hakluke - Thank you man for helping me fix that dumb bug :) 
- @vay3t - Go Help
- @BruceEdiger - Go Help
- @mortensonsam - Go help!!
- @xstp - stdin support
- https://www.golangprograms.com - A lot of the code here is copy-pasted from the internet, at the time of writing, my go skills are copy-paste :P And that's ok if it works, right?
