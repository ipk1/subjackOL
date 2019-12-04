package subjack

import (
	"bytes"
	"fmt"
	"strings"
	"github.com/haccer/available"
)

type Fingerprints struct {
	Service    		 	string   `json:"service"`
	Cname       		[]string `json:"cname"`
	Fingerprint 		[]string `json:"fingerprint"`
	FingerprintHeader   []string `json:"fingerprintHeader"`
	Nxdomain    		bool     `json:"nxdomain"`
	StatusCode  		[]int    `json:"statusCode"`
	IgnoreOptionA  bool     `json:"ignoreOptionA"`
}

/*
* Triage step to check whether the CNAME matches
* the fingerprinted CNAME of a vulnerable cloud service.
 */

func VerifyCNAME(subdomain string, config []Fingerprints) (match bool,cnameMatch string) {
	cname := resolve(subdomain)
	match = false

VERIFY:
	for n := range config {
		for c := range config[n].Cname {
			if strings.Contains(cname, config[n].Cname[c]) {
				match = true
				cnameMatch = config[n].Service
				break VERIFY
			}
		}
	}

	return match,cnameMatch
}

func detect(url, output string, ssl, verbose, manual bool, timeout int, config []Fingerprints,serviceCNAMEmatch string, isAll bool) {
	service := Identify(url, ssl, manual, timeout, config,serviceCNAMEmatch, isAll)

	if service != "" {
		result := fmt.Sprintf("[%s] %s\n", service, url)
		c := fmt.Sprintf("\u001b[32;1m%s\u001b[0m", service)
		out := strings.Replace(result, service, c, -1)
		fmt.Printf(out)

		if output != "" {
			if chkJSON(output) {
				writeJSON(service, url, output)
			} else {
				write(result, output)
			}
		}
	}

	if service == "" && verbose {
		result := fmt.Sprintf("[Not Vulnerable] %s\n", url)
		c := "\u001b[31;1mNot Vulnerable\u001b[0m"
		out := strings.Replace(result, "Not Vulnerable", c, -1)
		fmt.Printf(out)

		if output != "" {
			if chkJSON(output) {
				writeJSON(service, url, output)
			} else {
				write(result, output)
			}
		}
	}
}

/*
* This function aims to identify whether the subdomain
* is attached to a vulnerable cloud service and able to
* be taken over.
 */
func Identify(subdomain string, forceSSL, manual bool, timeout int, fingerprints []Fingerprints,serviceCNAMEmatch string, isAll bool) (service string) {
	response := get(subdomain, forceSSL, timeout)

	body := response.Body()

	cname := resolve(subdomain)

	if len(cname) <= 3 {
		cname = ""
	}

	service = ""
	nx := nxdomain(subdomain)


	if !isAll{ // when dns replace fingerprint with only matching cname
		myfingerPrint:=make([]Fingerprints, 1)
		for f := range fingerprints {
			if fingerprints[f].Service == serviceCNAMEmatch{
				myfingerPrint[0]=fingerprints[f]
				break
			}
		}
		fingerprints=myfingerPrint
	}

IDENTIFY:
	for f := range fingerprints {
		if !(isAll && fingerprints[f].IgnoreOptionA){ // does not check when -a option is set and ignore is true...
			// Begin subdomain checks if the subdomain returns NXDOMAIN
			if nx {
				// Check if we can register this domain.
				dead := available.Domain(cname)
				if dead {
					service = "DOMAIN AVAILABLE - " + cname
					break IDENTIFY
				}

				// Check if subdomain matches fingerprinted cname
				if fingerprints[f].Nxdomain {
					for n := range fingerprints[f].Cname {
						if strings.Contains(cname, fingerprints[f].Cname[n]) {
							service = strings.ToUpper(fingerprints[f].Service)
							break IDENTIFY
						}
					}
				}

				// Option to always print the CNAME and not check if it's available to be registered.
				if manual && !dead && cname != "" {
					service = "DEAD DOMAIN - " + cname
					break IDENTIFY
				}
			}

			// Check if body matches fingerprinted response
			for n := range fingerprints[f].Fingerprint {
				if bytes.Contains(body, []byte(fingerprints[f].Fingerprint[n])) {
					service = strings.ToUpper(fingerprints[f].Service)
					break
				}
			}

			for n := range fingerprints[f].FingerprintHeader {
				if bytes.Contains(response.Header.Header(), []byte(fingerprints[f].FingerprintHeader[n])) {
					service = strings.ToUpper(fingerprints[f].Service)
					break
				}
			}

			for n := range fingerprints[f].StatusCode {
				if fingerprints[f].StatusCode[n] == response.StatusCode() {
					service = strings.ToUpper(fingerprints[f].Service)
					break
				}
			}
	}
}
	return service
}
