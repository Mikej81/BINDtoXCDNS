package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var processedFiles = make(map[string]bool)

func processSOA(parts []string, soaParams *SOAParameters) {
	// Simplified example: Extract values assuming parts are in expected positions
	soaParams.Refresh = extractSOAValue(parts[3])     // Refresh period
	soaParams.Retry = extractSOAValue(parts[4])       // Retry period
	soaParams.Expire = extractSOAValue(parts[5])      // Expire time
	soaParams.NegativeTTL = extractSOAValue(parts[6]) // Minimum TTL

	// Assuming TTL is set at the start of the SOA record
	ttl, _ := strconv.Atoi(strings.Fields(parts[0])[1])
	soaParams.TTL = ttl
}

func extractSOAValue(part string) int {
	// Remove non-numeric characters
	numericPart := strings.TrimFunc(part, func(r rune) bool {
		return !('0' <= r && r <= '9')
	})
	value, _ := strconv.Atoi(numericPart)
	return value
}

func isValidDNSRecord(dnsRecord DNSRecord) bool {

	if dnsRecord.ARecord != nil &&
		dnsRecord.ARecord.Name != "" &&
		!isInt(dnsRecord.ARecord.Name) &&
		len(dnsRecord.ARecord.Values) > 0 {
		return true
	}

	return dnsRecord.ARecord != nil ||
		dnsRecord.CNAMERecord != nil ||
		dnsRecord.MXRecord != nil ||
		dnsRecord.TXTRecord != nil ||
		dnsRecord.AAAARecord != nil ||
		dnsRecord.NSRecord != nil ||
		dnsRecord.SRVRecord != nil
}

func isInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func processZoneBlock(zoneLines []string) (string, string, error) {
	var zoneFilePath, domainName string
	for _, line := range zoneLines {
		if strings.HasPrefix(line, "zone") {
			// Extract the domain name
			matches := regexp.MustCompile(`zone\s+"([^"]+)"`).FindStringSubmatch(line)
			if len(matches) > 1 {
				domainName = matches[1]
			}
		} else if strings.Contains(line, "file") {
			// Extract the file path
			matches := regexp.MustCompile(`file\s+"([^"]+)"`).FindStringSubmatch(line)
			if len(matches) > 1 {
				zoneFilePath = matches[1]
			}
		}
	}

	return domainName, zoneFilePath, nil
}

func ParseZoneFile(filePath string) (*ZoneConfig, error) {

	if processedFiles[filePath] {
		fmt.Printf("Skipping already processed file: %s\n", filePath)
		return nil, fmt.Errorf("file already processed: %s", filePath)
	}
	processedFiles[filePath] = true

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var defaultTTL string
	var lastTTL int
	var origin string
	var lastHostname string = "@" // Assume root by default for records without an explicit hostname
	var lastRecordType string     // Flag for null hostnames to join into array
	var inSOARecord bool          // Flag to indicate if we're currently processing an SOA record
	var soaLines []string         // Temporarily store SOA record lines for processing
	var records []DNSRecord
	var inZoneBlock bool // Flag to indicate we're currently processing a zone block for includes
	var zoneConfigLines []string
	_ = defaultTTL // shut up errors

	zoneConfig := &ZoneConfig{}
	zoneConfig.Metadata.Labels = make(map[string]string)
	zoneConfig.Metadata.Annotations = make(map[string]string)
	zoneConfig.Metadata.Description = "Zone Converted from BIND Zone File by MC Tool"

	// Outside the parsing loop, prepare to collect NS / A records
	rootNSRecords := []string{}                     // For root-level NS records
	subdomainNSRecords := make(map[string][]string) // For subdomain-specific NS records

	rootARecords := []string{}                     // For accumulating A record values by hostname
	subdomainARecords := make(map[string][]string) // For accumulating A record values by hostname

	for scanner.Scan() {
		line := scanner.Text() // Use the original line with leading spaces for whitespace detection
		trimmedLine := strings.TrimSpace(line)

		// Skip comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, ";") {
			continue
		}

		// Special handling for $ORIGIN
		if strings.HasPrefix(trimmedLine, "$ORIGIN") {
			origin = strings.Fields(trimmedLine)[1]
			zoneConfig.Metadata.Name = origin
			continue
		}
		// Special handling for $TTL
		if strings.HasPrefix(trimmedLine, "$TTL") {
			//defaultTTL := strings.Fields(trimmedLine)[1] // Keep defaultTTL as a string
			// implement something to take default TTL?
			continue
		}

		if inSOARecord || strings.Contains(trimmedLine, "SOA") {
			soaLines = append(soaLines, trimmedLine)
			// Check if this is the last line of the SOA record
			if strings.Contains(line, ")") {
				inSOARecord = false // We've reached the end of the SOA record
				processSOA(soaLines, &zoneConfig.Spec.Primary.SOAParameters)
				soaLines = []string{} // Reset for safety
			} else {
				inSOARecord = true // Continue collecting SOA lines
			}
			continue
		}

		// Handle the start and end of a zone block
		if !inZoneBlock && strings.HasPrefix(trimmedLine, "zone \"") {
			inZoneBlock = true
			zoneConfigLines = []string{trimmedLine} // Start a new zone config block
		} else if inZoneBlock {
			zoneConfigLines = append(zoneConfigLines, trimmedLine)
			if strings.HasSuffix(trimmedLine, "};") {
				inZoneBlock = false // End of zone config block
				domainName, zoneFilePath, err := processZoneBlock(zoneConfigLines)
				if err != nil {
					fmt.Printf("Error processing zone block: %v\n", err)
					continue
				}
				// Now domainName can be used for the output filename
				if domainName != "" && zoneFilePath != "" {
					fmt.Printf("Processing %s from %s\n", domainName, zoneFilePath)

					processIncludedZoneFile(zoneFilePath, domainName+".json")
				}
			}
		}

		// Main parsing logic for other record types
		parts := strings.Fields(trimmedLine)

		// Detect whether the line starts with whitespace indicating continuation of previous record
		startsWithWhitespace := line[0] == ' ' || line[0] == '\t'

		var ttl int
		var hostname, recordType string
		var values []string
		var recordValueStartIndex int = -1
		_ = values

		// Determine if the line starts with a TTL or a hostname
		if isInt(parts[0]) && !inZoneBlock { // Line starts with TTL, indicating either continuation or root-level record
			ttl, _ = strconv.Atoi(parts[0])
			recordType = parts[1]
			values = parts[2:]
			if !startsWithWhitespace { // Update TTL only if it's a new record
				lastTTL = ttl
			}
		} else if !isInt(parts[0]) && !inZoneBlock && len(parts) > 2 {
			hostname = parts[0]
			// Check if the hostname is actually "IN", indicating the record class, not a hostname
			if hostname == "IN" {
				// Adjust indices to correctly parse the line when "IN" is present
				ttl, _ = strconv.Atoi(parts[0]) // Use the first part as TTL
				recordType = parts[1]           // Adjust according to the actual format
				values = parts[2:]              // The rest of the parts are values
				hostname = ""                   // Set hostname to empty string
			} else {
				// Proceed as normal if the first part is a genuine hostname
				ttl, _ = strconv.Atoi(parts[1])
				recordType = parts[2]
				values = parts[3:]
				lastTTL = ttl
				lastHostname = hostname // Update the last known hostname for potential continuation
			}
		}

		// If the line is a continuation of the previous record, inherit the last known hostname and record type
		if startsWithWhitespace && lastRecordType == recordType {
			hostname = lastHostname
		} else {
			lastRecordType = recordType // Update the last known record type
		}

		for i, part := range parts {
			if strings.Contains(" NS MX A AAAA TXT CNAME SRV ", " "+part+" ") {
				recordType = part
				recordValueStartIndex = i + 1
				if i > 0 && isInt(parts[0]) {
					ttl, _ = strconv.Atoi(parts[0])
					lastTTL = ttl
				} else {
					ttl = lastTTL
				}
				if i == 2 { // Hostname is present
					hostname = parts[0]
				}
				break
			}
		}

		// if recordValueStartIndex == -1 {
		// 	fmt.Println("Warning: Record type not identified or unsupported in line:", line)
		// 	continue
		// }

		var dnsRecord DNSRecord

		switch recordType {
		case "A":
			// Parse A record
			if len(parts) > recordValueStartIndex {
				var root bool
				var hostname string

				root = true
				hostname = "@"

				if parts[0] == "@" || parts[0] == "" || isInt(parts[0]) {
					hostname = "@"
					root = true
				} else {
					hostname = parts[0]
					root = false
				}

				if root {
					rootARecords = append(rootARecords, parts[recordValueStartIndex])
				} else {
					subdomainARecords[hostname] = append(subdomainARecords[hostname], parts[recordValueStartIndex])
				}
			}
		case "NS":
			// Parse NS record
			if len(parts) > recordValueStartIndex {
				var root bool
				var hostname string

				root = true
				hostname = "@"

				if parts[0] == "@" || parts[0] == "" || isInt(parts[0]) || parts[0] == "IN" {
					hostname = "@"
					root = true
				} else {
					hostname = parts[0]
					root = false
				}

				if root {
					rootNSRecords = append(rootNSRecords, parts[recordValueStartIndex])
				} else {
					subdomainNSRecords[hostname] = append(subdomainNSRecords[hostname], parts[recordValueStartIndex])
				}

			}
		case "CNAME":
			// Parse CNAME record
			if len(parts) > recordValueStartIndex {
				hostname := parts[0] // Assuming the first part is always the hostname
				value := parts[recordValueStartIndex]
				dnsRecord := DNSRecord{
					TTL:         ttl,
					CNAMERecord: &CNAMERecord{Name: hostname, Value: value},
				}
				if isValidDNSRecord(dnsRecord) {
					records = append(records, dnsRecord)
				}
			}
		case "SRV":
			// Parse CNAME record
			if len(parts) > recordValueStartIndex {
				hostname := parts[0] // Assuming the first part is always the hostname
				value := parts[recordValueStartIndex]
				dnsRecord := DNSRecord{
					TTL:       ttl,
					SRVRecord: &SRVRecord{Name: hostname, Values: []string{value}},
				}
				if isValidDNSRecord(dnsRecord) {
					records = append(records, dnsRecord)
				}
			}
		// case "CAA":
		// 	// Parse CAA record
		// 	if len(parts) > recordValueStartIndex {
		// 		hostname := parts[0] // Assuming the first part is always the hostname
		// 		value := parts[recordValueStartIndex]
		// 		dnsRecord := DNSRecord{
		// 			TTL:         ttl,
		// 			CNAMERecord: &CNAMERecord{Name: hostname, Value: value},
		// 		}
		// 		if isValidDNSRecord(dnsRecord) {
		// 			records = append(records, dnsRecord)
		// 		}
		// 	}
		case "TXT":
			// Parse TXT record
			if len(parts) > recordValueStartIndex {
				// TXT records might not have a hostname
				hostname := parts[0] // Assuming the first part is always the hostname
				value := strings.Join(parts[recordValueStartIndex:], " ")

				if len(parts) >= 3 && isInt(parts[0]) && parts[1] == "TXT" {
					hostname = ""
				}
				dnsRecord := DNSRecord{
					TTL:       ttl,
					TXTRecord: &TXTRecord{Name: hostname, Values: []string{value}},
				}
				if isValidDNSRecord(dnsRecord) {
					records = append(records, dnsRecord)
				}
			}
		case "MX":
			if len(parts) > recordValueStartIndex+1 {
				priority, err := strconv.Atoi(parts[recordValueStartIndex])
				if err != nil {
					fmt.Println("Error parsing MX record priority:", parts[recordValueStartIndex])
					continue
				}
				mailServer := parts[recordValueStartIndex+1]
				dnsRecord.MXRecord = &[]MXValue{{Priority: priority, Value: mailServer}}
			}
		case "AAAA":
			if len(parts) > recordValueStartIndex {
				ipv6Address := parts[recordValueStartIndex]
				dnsRecord.AAAARecord = &[]string{ipv6Address} // Assuming AAAARecord is similarly structured to ARecord
				if hostname != "" {
					// If there's a specific way to handle hostname for AAAA records, do it here
				}
			}
		}

		//}
	}

	// After parsing, create DNSRecord entries for the NS records
	// I should actually just block Root Level NS since it will break...
	if len(rootNSRecords) > 0 {
		nsRecord := DNSRecord{
			TTL:      86400, // Or determine TTL differently
			NSRecord: &NSRecord{Values: rootNSRecords},
		}
		records = append(records, nsRecord)
	}

	for subdomain, nsValues := range subdomainNSRecords {
		nsRecord := DNSRecord{
			TTL:      86400,
			NSRecord: &NSRecord{Name: subdomain, Values: nsValues},
		}

		records = append(records, nsRecord)
	}

	if len(rootARecords) > 0 {
		aRecord := DNSRecord{
			TTL:      86400, // Or determine TTL differently
			NSRecord: &NSRecord{Values: rootARecords},
		}
		records = append(records, aRecord)
	}

	// After parsing, create DNSRecord entries for the A records similarly to NS records
	for hostname, values := range subdomainARecords {
		aRecord := DNSRecord{
			TTL:     60,
			ARecord: &ARecord{Name: hostname, Values: values},
		}
		records = append(records, aRecord)
	}

	zoneConfig.Metadata.Name = origin
	zoneConfig.Spec.Primary.DefaultRRSetGroup = records
	zoneConfig.Spec.Primary.DNSSECMode = DNSSECMode{Disable: DisabledType{}}

	// Use 'origin' after ensuring it's captured
	if origin != "" {
		zoneConfig.Metadata.Name = origin
	} else {
		// Handle the case where $ORIGIN might not be present or needed
		fmt.Println("Notice: $ORIGIN not specified, using a default or existing zoneConfig.Metadata.Name value.")
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return zoneConfig, nil
}

func processIncludedZoneFile(zoneFilePath, outputFileName string) {

	// Parse the zone file
	zoneConfig, err := ParseZoneFile(zoneFilePath)
	if err != nil {
		fmt.Printf("Error parsing zone file: %v\n", err)
		return
	}

	// Marshal the zone configuration to JSON
	jsonBytes, err := json.MarshalIndent(zoneConfig, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}

	// Write the JSON output to the specified file
	err = os.WriteFile(outputFileName, jsonBytes, 0644)
	if err != nil {
		fmt.Printf("Error writing to output file: %v\n", err)
		return
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: program <input_zone_file> <output_json_file>")
		return
	}

	inputFilePath := os.Args[1]
	outputFilePath := os.Args[2]

	// Parse the zone file
	zoneConfig, err := ParseZoneFile(inputFilePath)
	if err != nil {
		fmt.Printf("Error parsing zone file: %v\n", err)
		return
	}

	// Marshal the zone configuration to JSON
	jsonBytes, err := json.MarshalIndent(zoneConfig, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}

	// Write the JSON output to the specified file
	err = os.WriteFile(outputFilePath, jsonBytes, 0644)
	if err != nil {
		fmt.Printf("Error writing to output file: %v\n", err)
		return
	}

	fmt.Printf("Successfully wrote JSON output to %s\n", outputFilePath)
}
