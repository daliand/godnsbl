package godnsbl

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

/*
Blacklists is the list of blackhole lists to check against
*/
var Blacklists = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"psbl.surriel.com",
	"ix.dnsbl.manitu.net",
	"dnsbl.sorbs.net",
	"blackholes.five-ten-sg.com",
	"combined.njabl.org",
	"l2.apews.org",
	"dnsbl-1.uceprotect.net",
	"dnsbl-2.uceprotect.net",
	"dnsbl-3.uceprotect.net",
	"spam.spamrats.com",
	"dnsbl.kempt.net",
	"b.barracudacentral.org",
	"dnsbl.spfbl.net"}

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
		Host: host}

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
			}
		}
	}

	rev, _ := ReverseIP(ip)
	fmt.Printf("host lookup: %s", rev)

	wg := &sync.WaitGroup{}
	res.Results = make([]Result, len(Blacklists))
	for i, source := range Blacklists {
		wg.Add(1)
		go func(i int, source string) {
			defer wg.Done()

			m := new(dns.Msg)
			host := fmt.Sprintf("%s.%s", rev, Blacklists[i])
			m.SetQuestion(dns.Fqdn(host), dns.TypeA)

			r, err := dns.Exchange(m, fmt.Sprintf("%s:%d", server, port))
			if err != nil {
				res.Results[i].ErrorType = err
			}
			if r == nil || r.Rcode != dns.RcodeSuccess {
				res.Results[i].ErrorType = err
			}
			if r.Rcode == dns.RcodeNameError {
				res.Results[i].Listed = false
				res.Results[i].Rcode = r.Rcode
			} else {
				res.Results[i].Listed = true
				res.Results[i].Rcode = r.Rcode
			}
			res.Results[i].List = source
			res.Results[i].LookupHost = host

		}(i, source)
	}

	wg.Wait()

	return res
}
