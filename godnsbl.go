package godnsbl

import (
	"fmt"
	"net"
	"strings"

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
	"b.barracudacentral.org"}

/*
RBLResults holds the results of the lookup.
*/
type RBLResults struct {
	// Host is the host or IP that was passed (i.e. smtp.gmail.com)
	Host string `json:"host"`
	// Results is a slice of Results - one per IP address searched
	Results []Result `json:"results"`
}

/*
Result holds the individual IP lookup results for each RBL search
*/
type Result struct {
	// List is the RBL that was searched
	List string `json:"address"`
	// Listed indicates whether or not the IP was on the RBL
	Listed bool `json:"listed"`
	// RBL lists sometimes add extra information as a TXT record
	// if any info is present, it will be stored here.
	Text string `json:"text"`
	// Error represents any error that was encountered (DNS timeout, host not
	// found, etc.) if any
	Error bool `json:"error"`
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

	s := strings.Split(ip.String(), ".")

	return fmt.Sprintf("%s.%s.%s.%s", s[3], s[2], s[1], s[0]), nil
}

func Lookup(ip net.IP) RBLResults {

	res := RBLResults{
		Host: ip.String()}

	rev, _ := ReverseIP(ip)

	for _, bl := range Blacklists {
		re := Result{
			List: bl}

		m := new(dns.Msg)
		host := fmt.Sprintf("%s.%s.", rev, bl)
		m.SetQuestion(host, dns.TypeA)

		r, err := dns.Exchange(m, "8.8.8.8:53")
		if err != nil {
			re.ErrorType = err
		}
		if r == nil || r.Rcode != dns.RcodeSuccess {
			re.ErrorType = err
		}
		res.Results = append(res.Results, re)
	}

	return res
}
