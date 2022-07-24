package internal

import (
	"encoding/json"
	"fmt"
	"golang.org/x/exp/maps"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Certificate struct used to hold the data of each certificate returned from crt.sh .
type Certificate struct {
	IssuerCaId     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	Id             int    `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

type Flags struct {
	Domain      string
	PlainOutput bool
	WordsFile   string
}

// DNSLookupResult struct used to store the domain name and the list of IP address to which this domain name is resolved.
type DNSLookupResult struct {
	Domain string
	Ips    []net.IP
}

func Execute(flags *Flags) error {
	ch := make(chan []byte)
	errCh := make(chan error)
	params := map[string]string{
		"q":        flags.Domain,
		"output":   "json",
		"excluded": "expired",
	}
	go fetchResource("https://crt.sh", params, ch, errCh)

	select {
	case resp := <-ch:
		var certificates []Certificate

		if err := json.Unmarshal(resp, &certificates); err != nil {
			fmt.Println(string(resp))
			return err
		}

		domains, extendedDomains := getResolvableDomains(certificates, flags)
		printDomains(domains, extendedDomains, flags.PlainOutput)

	case e := <-errCh:
		return e
	}

	return nil
}

// Fetch the resource from an url with additional query params
func fetchResource(u string, params map[string]string, ch chan<- []byte, errorCh chan<- error) {
	urlValues := url.Values{}
	for key, value := range params {
		urlValues.Add(key, value)
	}
	var encodedParams string
	if len(urlValues) > 0 {
		encodedParams = "?" + urlValues.Encode()
	}

	q, _ := http.NewRequest("GET", u+encodedParams, nil)
	client := http.Client{}

	handleError := func(err error) {
		errorCh <- err
	}

	resp, err := client.Do(q)
	if err != nil {
		defer handleError(err)
		return
	}

	if body, err := io.ReadAll(resp.Body); err == nil {
		ch <- body
	} else {
		defer handleError(err)
		return
	}

	if err := resp.Body.Close(); err != nil {
		defer handleError(err)
	}
}

// Returns 2 slices each containing only domain names which can be resolved to an IP address. If a file is provided
// with a list of words, this function will attempt to extend all wildcard domains and return only those which are
// resolvable to an IP address. If there is no file provided, the secondary return value be an empty slice.
func getResolvableDomains(certificates []Certificate, flags *Flags) ([]string, []string) {
	uniqDomains := make(map[string]bool)
	for _, cert := range certificates {
		uniqDomains[cert.CommonName] = true
		nameValues := strings.Split(cert.NameValue, "\n")
		for _, nameValue := range nameValues {
			uniqDomains[nameValue] = true
		}
	}

	wildCardDomains, domains := partitionDomains(cleanDomainNames(maps.Keys(uniqDomains)))

	var uniqPotentialDomains []string

	if len(flags.WordsFile) > 0 {
		if potentialDomains, err := extendWildcardDomains(wildCardDomains, flags.WordsFile); err == nil {
			// Filter domains which do already exist in the non-wildcard collection
			uniqPotentialDomains = append(uniqPotentialDomains, computeDifference(domains, potentialDomains)...)
		}
	}

	return domains, uniqPotentialDomains
}

// Helper function used to remove potential whitespace characters from the beginning and from the end of each domain
// name from the input slice.
func cleanDomainNames(domains []string) []string {
	var cleanDomains []string
	for _, domain := range domains {
		cleanDomains = append(cleanDomains, strings.TrimSpace(domain))
	}
	return cleanDomains
}

// Partitions the domains based on the condition if they contain a wildcard ("*") or not.
// Returns two slices, the first one contains the wildcard domains, the second on contains the non-wildcard domains.
func partitionDomains(domains []string) ([]string, []string) {
	var wildCards []string
	var nonWildCards []string
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*") {
			wildCards = append(wildCards, domain)
		} else {
			nonWildCards = append(nonWildCards, domain)
		}
	}
	return wildCards, nonWildCards
}

// Replace wildcard ("*") part of the domain with each world from the file provided.
func extendWildcardDomains(domains []string, wordsPath string) ([]string, error) {
	content, err := ioutil.ReadFile(wordsPath)
	if err != nil {
		return nil, err
	}

	var words []string

	for _, line := range strings.Split(string(content), "\n") {
		words = append(words, strings.TrimSpace(line))
	}

	var potentialDomains []string
	for _, domain := range domains {
		for _, word := range words {
			potentialDomains = append(potentialDomains, strings.Replace(domain, "*", word, 1))
		}
	}

	return potentialDomains, nil
}

// Return the difference between "potentialDomains" slice and "domains" slice. Equivalent of B - A set operation.
func computeDifference(domains []string, potentialDomains []string) []string {
	var nonWild = make(map[string]bool)
	for _, domain := range domains {
		nonWild[domain] = true
	}

	var uniqPotentialDomains []string
	for _, domain := range potentialDomains {
		if _, exists := nonWild[domain]; !exists {
			uniqPotentialDomains = append(uniqPotentialDomains, domain)
		}
	}

	return uniqPotentialDomains
}

// Pretty print two slices with domain names
func printDomains(domains []string, extendedDomains []string, plain bool) {
	printReachableDomains(domains, plain)

	if len(extendedDomains) > 0 {
		if !plain {
			fmt.Printf("\nExtended domains:\n")
		}
		printReachableDomains(extendedDomains, plain)
	}
}

// Print a list with domains. If the "plain" flag is set, the IP address to which the domain is resolved,
// will not be printed.
func printReachableDomains(domain []string, plain bool) {
	ch := make(chan DNSLookupResult, len(domain))
	errCh := make(chan string, len(domain))
	for _, domain := range domain {
		go lookUpDns(domain, ch, errCh)
	}

	for range domain {
		select {
		case resp := <-ch:
			if plain {
				fmt.Printf("%s\n", resp.Domain)
				continue
			}
			fmt.Printf("%s - IPs: %s\n", resp.Domain, resp.Ips)
		case e := <-errCh:
			_ = e
		}
	}
}

// Attempt to do DNS resolution on a domain name.
func lookUpDns(domain string, ch chan<- DNSLookupResult, errCh chan<- string) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		errCh <- domain
		return
	}
	ch <- DNSLookupResult{Domain: domain, Ips: ips}
}
