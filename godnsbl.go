package godnsbl

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

/*
Blacklists is the list of blackhole lists to check against
*/
var (
	Blacklists = []string{
		"zen.spamhaus.org",
		"bl.spamcop.net",
		"psbl.surriel.com",
		"ix.dnsbl.manitu.net",
		"dnsbl.sorbs.net",
		"blackholes.five-ten-sg.com",
		// "combined.njabl.org",  // timing out
		"l2.apews.org",
		"dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net",
		"spam.spamrats.com",
		"dnsbl.kempt.net",
		"b.barracudacentral.org",
		"dnsbl.spfbl.net",
	}
)

/*
RBLResults holds the results of the lookup.
*/
type RBLResults struct {
	// Host is the host or IP that was passed (i.e. smtp.gmail.com)
	Host  string `json:"host"`
	Err   error  `json:"err"`
	RCode int
	// Results is a slice of Results - one per Blacklist address searched
	Results []Result `json:"results"`
}

/*
Result holds the individual IP lookup results for each RBL search
*/
type Result struct {
	// List is the RBL that was searched
	List       string `json:"address"`
	LookupHost string `json:"lookup"`
	// Listed indicates whether or not the IP was on the RBL
	Listed bool `json:"listed"`
	// RBL lists sometimes add extra information as a TXT record
	// if any info is present, it will be stored here.
	Text string `json:"text"`
	// Error represents any error that was encountered (DNS timeout, host not
	// found, etc.) if any
	Rcode int `json:"rcode"`
	// TTL is the DNS ttl returned
	TTL uint32 `json:"ttl"`
	// ErrorType is the type of error encountered if any
	ErrorType error `json:"error_type"`
}

// SetResolver sets the DNS servers and port to use
// func SetResolver(server string, port int) error {

// 	Resolver := new(dns.Client)
// 	conn, err := Resolver.Dial(fmt.Sprintf("%s:%d", server, port))
// 	if err != nil {
// 		return err
// 	}

// 	if conn == nil {
// 		return ErrDNSTimeout
// 	}
// 	return nil
// }

// ReverseIP reverses the IP address octets
func ReverseIP(ip net.IP) (string, error) {
	if ip.To4() == nil {
		return "", ErrInvalidIP
	}
	// split into slice by dot .
	addressSlice := strings.Split(ip.String(), ".")
	reverseSlice := []string{}

	for i := range addressSlice {
		octet := addressSlice[len(addressSlice)-1-i]
		reverseSlice = append(reverseSlice, octet)
	}

	return strings.Join(reverseSlice, "."), nil
}

// Lookup Queries []Blacklists against a server
// TODO: init the library with multiple servers
func Lookup(host, server string, port int) RBLResults {

	res := RBLResults{
		Host: host,
	}

	ip := net.ParseIP(host)

	// We're dealing with host
	if ip == nil {
		am := new(dns.Msg)
		am.SetQuestion(dns.Fqdn(host), dns.TypeA)
		ar, aerr := dns.Exchange(am, fmt.Sprintf("%s:%d", server, port))
		if aerr != nil {
			res.Err = aerr
			return res
		}
		if ar.Rcode != dns.RcodeSuccess {
			res.RCode = ar.Rcode
			return res
		}
		for _, a := range ar.Answer {
			if mx, ok := a.(*dns.A); ok {
				ip = mx.A
				break
			}
		}
	}

	rev, revErr := ReverseIP(ip)
	if revErr != nil {
		return res
	}
	// fmt.Printf("ReverseIP host lookup: %s\n", rev)

	wg := &sync.WaitGroup{}
	res.Results = make([]Result, len(Blacklists))
	for i, source := range Blacklists {
		wg.Add(1)
		go func(i int, source string) {
			defer wg.Done()
			res.Results[i].List = source

			m := new(dns.Msg)
			host := fmt.Sprintf("%s.%s", rev, Blacklists[i])
			m.SetQuestion(dns.Fqdn(host), dns.TypeA)
			res.Results[i].LookupHost = host

			r, err := dns.Exchange(m, fmt.Sprintf("%s:%d", server, port))
			if err != nil {
				res.Results[i].ErrorType = err
			}
			if r != nil {
				res.Results[i].Rcode = r.Rcode
				switch r.Rcode {
				case dns.RcodeSuccess:
					if len(r.Answer) > 0 && r.Answer[0].Header() != nil {
						res.Results[i].Listed = true
						res.Results[i].TTL = r.Answer[0].Header().Ttl
					}
				case dns.RcodeNameError:
					// correct response code when not listed
					res.Results[i].Listed = false
				case dns.RcodeServerFailure:
					// we cant be sure this is listed
					res.Results[i].Listed = false
					if res.Results[i].ErrorType == nil {
						res.Results[i].ErrorType = errors.New("Server failure")
					}
				}
			}
		}(i, source)
	}

	wg.Wait()

	return res
}
