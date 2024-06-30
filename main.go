package main

import (
    "bufio"
    "encoding/json"
    "encoding/xml"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "sort"
    "strings"

    "github.com/n0ncetonic/nmapxml"
)

type parse struct {
    nmapxml.Run
}

func main() {
    var inputArg = flag.String("x", "", "Nmap XML Input File (Required)")
    var ipportArg = flag.String("i", "", "IP:Port Input File (Optional)")
    var dnsxArg = flag.String("dnsx", "", "dnsx -resp output data (Optional)")
    var vhostRep = flag.Bool("vhost", false, "Use dnsx data to insert vhosts (Optional)")
    var includeOrphanedIpsArg = flag.Bool("include-orphaned-ips", false, "Include IP:port even with vhost (Optional)")
    var urlArg = flag.Bool("urls", false, "Guess HTTP URLs from input (Optional)")
    var outputArg = flag.String("o", "", "Output filename (Optional)")

    flag.Parse()
    var results []string

    input := *inputArg
    ipport := *ipportArg
    output := *outputArg
    dnsx := *dnsxArg
    vhost := *vhostRep
    includeOrphanedIps := *includeOrphanedIpsArg
    urls := *urlArg

    if (input == "") && (ipport == "") {
        flag.PrintDefaults()
        os.Exit(1)
    }

    if input != "" {
        results = parse{}.parseNmap(input, dnsx, vhost, includeOrphanedIps, urls)
    } else if ipport != "" {
        results = parseIpport(ipport, dnsx, vhost, includeOrphanedIps, urls)
    }

    results = unique(results)

    // Remove ip:port entries for IPs that have associated domains
    if vhost {
        ipSet := make(map[string]bool)       // Set to track unique IPs
        domainSet := make(map[string]bool)   // Set to track unique domains
        updatedResults := []string{}         // List to store filtered results

        // First pass: Populate ipSet and domainSet
        for _, line := range results {
            parts := strings.Split(line, ":")
            if len(parts) == 2 {
                if net.ParseIP(parts[0]) != nil {
                    ipSet[parts[0]] = true
                } else {
                    domainSet[parts[0]] = true
                }
            }
        }

        // Second pass: Filter results based on ipSet and domainSet
        for _, line := range results {
            parts := strings.Split(line, ":")
            if len(parts) == 2 {
                ip := parts[0]    // The first part is considered as the IP address or domain
                port := parts[1]  // The second part is considered as the port number

                // Check if the first part is a valid IP address
                if net.ParseIP(ip) != nil {
                    // If the IP address is not in domainSet or the port is neither 80 nor 443
                    if !domainSet[ip] || (port != "80" && port != "443") {
                        updatedResults = append(updatedResults, line)
                    }
                } else {
                    updatedResults = append(updatedResults, line)
                }
            } else {
                // Handle case where there is no port part (likely a URL)
                updatedResults = append(updatedResults, line)
            }
        }

        results = updatedResults
    }

    sort.Strings(results)

    for _, line := range results {
        fmt.Println(line)
    }

    if output != "" {
        file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("failed creating file: %s", err)
        }

        datawriter := bufio.NewWriter(file)
        for _, data := range results {
            datawriter.WriteString(data + "\n")
        }

        datawriter.Flush()
        file.Close()
    }
}

func unique(slice []string) []string {
    uniqMap := make(map[string]struct{})
    for _, v := range slice {
        uniqMap[v] = struct{}{}
    }

    uniqSlice := make([]string, 0, len(uniqMap))
    for v := range uniqMap {
        uniqSlice = append(uniqSlice, v)
    }

    return uniqSlice
}

func parseIpport(input string, dnsx string, vhost bool, includeOrphanedIps bool, urls bool) []string {
    var index map[string][]string
    var output []string

    if input != "-" {
        if _, err := os.Stat(input); err != nil {
            fmt.Printf("File does not exist\n")
            os.Exit(1)
        }
    }

    if dnsx != "" {
        if _, err := os.Stat(dnsx); err != nil {
            fmt.Printf("dnsx file does not exist\n")
        } else {
            index = parseDnsx(dnsx)
        }
    }

    file, err := os.Open(input)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        s := strings.Split(scanner.Text(), ":")
        ip, port := s[0], s[1]
        service := ""

        if strings.Contains(port, "80") {
            service = "http"
        } else if strings.Contains(port, "443") {
            service = "https"
        }

        resp := processData(ip, port, service, vhost, includeOrphanedIps, urls, index)
        output = append(output, resp...)
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    return output
}

func (p parse) parseNmap(input string, dnsx string, vhost bool, includeOrphanedIps bool, urls bool) []string {
    var index map[string][]string
    var output []string

    if input != "-" {
        if _, err := os.Stat(input); err != nil {
            fmt.Printf("File does not exist\n")
            os.Exit(1)
        }

        p.Run, _ = nmapxml.Readfile(input)
    } else {
        bytes, _ := ioutil.ReadAll(os.Stdin)
        xml.Unmarshal(bytes, &p.Run)
    }

    if dnsx != "" {
        if _, err := os.Stat(dnsx); err != nil {
            fmt.Printf("dnsx file does not exist\n")
        } else {
            index = parseDnsx(dnsx)
        }
    }

    for _, host := range p.Host {
        ipAddr := host.Address.Addr
        if host.Ports.Port != nil {
            for _, portData := range *host.Ports.Port {
                if portData.State.State == "open" {
                    portID := portData.PortID
                    service := portData.Service.Name
                    resp := processData(ipAddr, portID, service, vhost, includeOrphanedIps, urls, index)
                    output = append(output, resp...)
                }
            }
        }
    }

    return output
}

func processData(ipAddr string, port string, service string, vhost bool, includeOrphanedIps bool, urls bool, index map[string][]string) []string {
    var output []string
    indexed, exists := index[ipAddr]

    // Check if the vhost option is enabled
    if vhost {
        // If the IP address has associated domains
        if exists {
            // Iterate over each domain associated with the IP address
            for _, dom := range indexed {
                var line string
                // If URL generation is enabled, generate a URL
                if urls {
                    line = generateURL(dom, port, service)
                } else {
                    // Otherwise, format as domain:port
                    line = dom + ":" + port
                }
                // Add the formatted string to the output list
                output = append(output, line)
            }
        }
        // If includeOrphanedIps is enabled and the IP address has no associated domains
        if includeOrphanedIps && !exists {
            var line string
            // If URL generation is enabled, generate a URL
            if urls {
                line = generateURL(ipAddr, port, service)
            } else {
                // Otherwise, format as ip:port
                line = ipAddr + ":" + port
            }
            // Add the formatted string to the output list
            output = append(output, line)
        }
    } else {
        var line string
        // If URL generation is enabled, generate a URL
        if urls {
            line = generateURL(ipAddr, port, service)
        } else {
            // Otherwise, format as ip:port
            line = ipAddr + ":" + port
        }
        // Add the formatted string to the output list
        output = append(output, line)
    }

    return output
}

func generateURL(host string, port string, service string) string {
    var protocol string

    // Determine the protocol based on the service or port
    switch {
    case strings.Contains(service, "https"):
        protocol = "https://"
    case strings.Contains(service, "http"):
        protocol = "http://"
    case service == "ftp":
        protocol = "ftp://"
    case service == "ssh":
        protocol = "ssh://"
    case service == "telnet":
        protocol = "telnet://"
    case service == "smtp":
        protocol = "smtp://"
    case service == "imap":
        protocol = "imap://"
    case service == "pop3":
        protocol = "pop3://"
    case service == "sftp":
        protocol = "sftp://"
    case port == "21":
        protocol = "ftp://"
    case port == "22":
        protocol = "ssh://"
    case port == "23":
        protocol = "telnet://"
    case port == "25":
        protocol = "smtp://"
    case port == "80":
        protocol = "http://"
    case port == "110":
        protocol = "pop3://"
    case port == "143":
        protocol = "imap://"
    case port == "443":
        protocol = "https://"
    case port == "989", port == "990":
        protocol = "ftps://"
    case port == "993":
        protocol = "imaps://"
    case port == "995":
        protocol = "pop3s://"
    default:
        protocol = "unknown://"
    }

    // Format the URL based on the protocol and host
    var url string
    if protocol == "" {
        url = host + ":" + port
    } else if (port == "80" && protocol == "http://") || (port == "443" && protocol == "https://") {
        url = protocol + host
    } else {
        url = protocol + host + ":" + port
    }

    return url
}

func parseDnsx(filename string) map[string][]string {
    var data = map[string][]string{}
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        var result map[string]interface{}
        json.Unmarshal([]byte(scanner.Text()), &result)

        host, ok := result["host"].(string)
        if !ok {
            continue
        }

        if val, ok := result["a"]; ok {
            aRecords, ok := val.([]interface{})
            if !ok {
                continue
            }

            for _, record := range aRecords {
                ip, ok := record.(string)
                if ok {
                    data[ip] = append(data[ip], host)
                }
            }
        }
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    return data
}
