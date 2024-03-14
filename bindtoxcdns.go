package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Helper function to process SOA record parts and populate SOAParameters
func processSOA(parts []string, soaParams *SOAParameters) {
	// Simplified example: Extract values assuming parts are in expected positions
	// In a real scenario, more robust parsing with error checking is needed
	soaParams.Refresh = extractSOAValue(parts[3])     // Refresh period
	soaParams.Retry = extractSOAValue(parts[4])       // Retry period
	soaParams.Expire = extractSOAValue(parts[5])      // Expire time
	soaParams.NegativeTTL = extractSOAValue(parts[6]) // Minimum TTL

	// Assuming TTL is set at the start of the SOA record
	ttl, _ := strconv.Atoi(strings.Fields(parts[0])[1])
	soaParams.TTL = ttl
}

// Helper function to extract integer values from SOA record parts
func extractSOAValue(part string) int {
	// Remove non-numeric characters
	numericPart := strings.TrimFunc(part, func(r rune) bool {
		return !('0' <= r && r <= '9')
	})
	value, _ := strconv.Atoi(numericPart)
	return value
}

func isValidDNSRecord(dnsRecord DNSRecord) bool {
	// Checks if the dnsRecord is valid (not empty) based on your criteria.
	// For example, checking that at least one record type field is non-nil.
	return dnsRecord.ARecord != nil ||
		dnsRecord.CNAMERecord != nil ||
		dnsRecord.MXRecord != nil ||
		dnsRecord.TXTRecord != nil ||
		dnsRecord.AAAARecord != nil ||
		dnsRecord.NSRecord != nil // Extend this logic based on your record types
}

// Function to check if a string is an integer (to help identify TTLs)
func isInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func ParseZoneFile(filePath string) (*ZoneConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var records []DNSRecord
	var lastTTL int
	var origin string
	var inSOARecord bool  // Flag to indicate if we're currently processing an SOA record
	var soaLines []string // Temporarily store SOA record lines for processing

	zoneConfig := &ZoneConfig{}
	zoneConfig.Metadata.Labels = make(map[string]string)
	zoneConfig.Metadata.Annotations = make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "$ORIGIN") {
			origin = strings.Fields(line)[1]
			zoneConfig.Metadata.Name = origin
			continue
		}

		// Check if we're starting an SOA record
		if strings.Contains(line, "SOA") {
			inSOARecord = true
			soaLines = append(soaLines, line) // Add the first line of the SOA record
			continue
		}

		if inSOARecord {
			soaLines = append(soaLines, line)
			// Check if this is the last line of the SOA record
			if strings.Contains(line, ")") {
				inSOARecord = false // We've reached the end of the SOA record
				processSOA(soaLines, &zoneConfig.Spec.Primary.SOAParameters)
				soaLines = []string{} // Reset for safety
			}
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			fmt.Println("Warning: Skipping line due to insufficient parts:", line)
			continue
		}

		var ttl int
		var recordType string
		var hostname string
		var recordValueStartIndex int = -1

		for i, part := range parts {
			if strings.Contains(" NS MX A AAAA TXT CNAME ", " "+part+" ") {
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

		if recordValueStartIndex == -1 {
			fmt.Println("Warning: Record type not identified or unsupported in line:", line)
			continue
		}

		var dnsRecord DNSRecord
		//dnsRecord.TTL = ttl

		switch recordType {
		case "A":
			// Parse A record
			if len(parts) > recordValueStartIndex {
				// Assuming A records have a structure: [host] [ttl] A [value]
				hostname := parts[0] // Assuming the first part is always the hostname
				value := parts[recordValueStartIndex]
				dnsRecord := DNSRecord{
					TTL:     ttl,
					ARecord: &ARecord{Name: hostname, Values: []string{value}},
				}
				if isValidDNSRecord(dnsRecord) {
					records = append(records, dnsRecord)
				}
			}
		case "NS":
			// Parse NS record
			if len(parts) > recordValueStartIndex {
				// Assuming A records have a structure: [host] [ttl] A [value]
				//hostname := parts[0] // Assuming the first part is always the hostname
				value := parts[recordValueStartIndex]
				dnsRecord := DNSRecord{
					TTL:      ttl,
					NSRecord: &NSRecord{Name: hostname, Values: []string{value}},
				}
				if isValidDNSRecord(dnsRecord) {
					records = append(records, dnsRecord)
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
				records = append(records, dnsRecord)
			}
		case "TXT":
			// Parse TXT record
			if len(parts) > recordValueStartIndex {
				// TXT records might not have a hostname; adjust as needed
				value := strings.Join(parts[recordValueStartIndex:], " ")
				dnsRecord := DNSRecord{
					TTL:       ttl,
					TXTRecord: &[]string{value},
				}
				records = append(records, dnsRecord)
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

		records = append(records, dnsRecord)
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
