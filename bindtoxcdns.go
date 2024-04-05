package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var processedFiles = make(map[string]bool)
var lastSeenCNAMEHostname string = ""

// This does nothing yet, I want to move the parsing of records into individual functions to account for better handling, so placeholder for future release

func processARecord(parts []string, lastHostname string) (DNSRecord, string, error) {
	var dnsRecord DNSRecord

	// Initial assumptions
	var recordHostname string
	var values []string
	var description string

	// Determine hostname and TTL
	if !isInt(parts[0]) && parts[0] != "IN" {
		recordHostname = parts[0]
		ttl, err := strconv.Atoi(parts[1])
		if err != nil {
			return DNSRecord{}, lastHostname, fmt.Errorf("invalid TTL: %v", err)
		}
		dnsRecord.TTL = ttl
		values = append(values, parts[3]) // Assuming the value is always the fourth part
	} else {
		recordHostname = lastHostname      // Use the last seen hostname if current is omitted
		ttl, err := strconv.Atoi(parts[0]) // Assuming TTL is the first part if hostname is omitted
		if err != nil {
			return DNSRecord{}, lastHostname, fmt.Errorf("invalid TTL: %v", err)
		}
		dnsRecord.TTL = ttl
		values = append(values, parts[2]) // Value is the third part if hostname is omitted
	}

	// Parse description if it exists
	for _, part := range parts {
		if strings.HasPrefix(part, ";") {
			//descriptionIndex := strings.Index(line, ";")
			//description = strings.TrimSpace(line[descriptionIndex+1:])
			break
		}
	}

	dnsRecord = DNSRecord{
		TTL:         86400, // Or determine TTL differently
		ARecord:     &ARecord{Values: values},
		Description: description,
	}

	return dnsRecord, recordHostname, nil // Return the updated lastHostname
}

func processSOA(parts []string, soaParams *SOAParameters) {
	// Simplified example: Extract values assuming parts are in expected positions
	soaParams.Refresh = extractSOAValue(parts[3]) // Refresh period
	if soaParams.Refresh < 3600 {
		soaParams.Refresh = 86400
	}
	soaParams.Retry = extractSOAValue(parts[4]) // Retry period
	if soaParams.Retry < 7200 {
		soaParams.Retry = 7200
	}
	soaParams.Expire = extractSOAValue(parts[5]) // Expire time
	if soaParams.Expire < soaParams.Refresh+soaParams.Retry {
		soaParams.Expire = 3600000
	}
	soaParams.NegativeTTL = extractSOAValue(parts[6]) // Minimum TTL

	// Assuming TTL is set at the start of the SOA record
	ttl, _ := strconv.Atoi(strings.Fields(parts[0])[1])
	soaParams.TTL = ttl
}

func processCNAME(line string, cnameRecordsMap map[string]*CNAMERecord, origin string, customOrigin string) error {
	// Normalize the line by converting tabs to spaces and trimming extra spaces
	normalizedLine := strings.Join(strings.Fields(strings.ReplaceAll(line, "\t", " ")), " ")

	// Split the line into parts
	parts := strings.Split(normalizedLine, " ")

	// Find index of "IN" and "CNAME" to determine structure
	inIndex := -1
	cnameIndex := -1
	for i, part := range parts {
		if part == "IN" {
			inIndex = i
		} else if part == "CNAME" {
			cnameIndex = i
			break
		}
	}

	// Validate indices
	if inIndex == -1 || cnameIndex == -1 || cnameIndex != inIndex+1 {
		return fmt.Errorf("invalid CNAME record format: missing 'IN CNAME'")
	}

	// Determine the hostname and value
	hostname := parts[0]
	if hostname == "@" {
		//return fmt.Errorf("Warning '@' is not a permitted hostname [%s], skipping record: %s\n", origin, line)
		hostname = origin
	} else if hostname == "" {
		// Use the last seen hostname if the current line does not specify one
		hostname = lastSeenCNAMEHostname
	} else {
		// Trim and sanitize the hostname
		hostname = strings.TrimSuffix(strings.TrimSpace(hostname), ".")
		lastSeenCNAMEHostname = hostname // Update the last seen hostname
	}

	valueIndex := cnameIndex + 1
	if valueIndex >= len(parts) {
		return fmt.Errorf("invalid CNAME record format: missing value")
	}
	isFQDN := false
	value := strings.TrimSpace(parts[valueIndex])
	value = strings.TrimSuffix(value, ".") // Ensure value does not end with a dot
	value, isFQDN = ensureFQDN(value, customOrigin)

	if !isFQDN {
		fmt.Printf(ColorRed+"Warning:"+ColorYellow+" Cannot Map, [%s.%s] not importing:"+ColorReset+" %s\n", origin, customOrigin, line)
		return nil
	}

	// Special use-case to skip a record if the hostname or value ends with .hsep
	if strings.HasSuffix(hostname, ".hsep") || strings.HasSuffix(value, ".hsep") {
		fmt.Printf(ColorRed+"Warning:"+ColorYellow+" Cannot Map, [%s.%s] not importing:"+ColorReset+" %s\n", origin, customOrigin, line)
		return nil // or return a special error if you want to handle this case differently
	}

	// Process the record
	if _, exists := cnameRecordsMap[hostname]; exists {
		fmt.Printf(ColorRed+"Warning:"+ColorYellow+" Duplicate CNAME record for hostname '%s', skipping:"+ColorReset+" %s\n", hostname, line)
		return nil
	} else {
		// Create a new CNAMERecord for this hostname
		cnameRecordsMap[hostname] = &CNAMERecord{
			Name:  hostname,
			Value: value,
		}
	}

	return nil
}

// Helper function to check if a slice contains a given string
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
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

func parseTTL(ttlStr string) (int, error) {
	// Enhanced regex pattern to capture numbers followed by an optional time unit (day, hour, minute)
	ttlPattern := regexp.MustCompile(`^(\d+)([dhmDHM]?)$`)
	matches := ttlPattern.FindStringSubmatch(ttlStr)

	if matches == nil {
		return 0, fmt.Errorf("invalid TTL format: %s", ttlStr)
	}

	// Parse the integer part of the TTL
	ttlValue, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid TTL value: %s", matches[1])
	}

	// Adjust TTL based on the time designation (if present), considering both uppercase and lowercase
	switch strings.ToUpper(matches[2]) {
	case "D":
		ttlValue *= 24 * 3600
	case "H":
		ttlValue *= 3600
	case "M":
		ttlValue *= 60
	}

	return ttlValue, nil
}

func isInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func recordKey(record DNSRecord) string {
	var builder strings.Builder

	// Use different structuring depending on the type of DNS record
	if record.ARecord != nil {
		builder.WriteString("A:")
		builder.WriteString(record.ARecord.Name)
	} else if record.SRVRecord != nil {
		builder.WriteString("SRV:")
		builder.WriteString(record.SRVRecord.Name)
		for _, value := range record.SRVRecord.Values {
			builder.WriteString(fmt.Sprintf(":%d:%d:%d:%s", value.Priority, value.Weight, value.Port, value.Target))
		}
	} else if record.MXRecord != nil {
		builder.WriteString("MX:")
		for _, value := range *record.MXRecord {
			builder.WriteString(fmt.Sprintf(":%d:%s", value.Priority, value.Value))
		}
	} else if record.TXTRecord != nil {
		builder.WriteString("TXT:")
		builder.WriteString(record.TXTRecord.Name)
		// Sort the values of the TXT record to ensure consistent order
		sortedValues := make([]string, len(record.TXTRecord.Values))
		copy(sortedValues, record.TXTRecord.Values)
		sort.Strings(sortedValues)
		builder.WriteString(":")
		builder.WriteString(strings.Join(sortedValues, ";"))
	} else if record.CNAMERecord != nil {
		builder.WriteString(fmt.Sprintf("CNAME:%s:%s", record.CNAMERecord.Name, record.CNAMERecord.Value))
	} else if record.CAARecord != nil {
		builder.WriteString(fmt.Sprintf("CAA:%s:%s:%s:%s", record.CAARecord.Name, record.CAARecord.Flags, record.CAARecord.Tag, record.CAARecord.Value))
	} else if record.NSRecord != nil {
		builder.WriteString("NS:")
		builder.WriteString(record.NSRecord.Name)
		for _, value := range record.NSRecord.Values {
			builder.WriteString(fmt.Sprintf(":%s", value))
		}
	} else if record.AAAARecord != nil {
		builder.WriteString("AAAA:")
		builder.WriteString(record.AAAARecord.Name)
		for _, value := range record.AAAARecord.Values {
			builder.WriteString(fmt.Sprintf(":%s", value))
		}
	}

	// Include TTL and description in the key to differentiate records with different TTLs or descriptions
	builder.WriteString(fmt.Sprintf("TTL:%d:Desc:%s", record.TTL, record.Description))

	return builder.String()
}

func deduplicateAndMergeDNSRecords(records []DNSRecord) []DNSRecord {
	mergedRecords := make([]DNSRecord, 0)
	recordMap := make(map[string]*DNSRecord)

	for _, record := range records {
		key := recordKeyForMerging(record)
		if existingRecord, found := recordMap[key]; found {
			// Merge values if the record supports it and is not a duplicate
			mergeRecordValues(existingRecord, &record)
		} else {
			// If not found, add record to map and list
			recordMap[key] = &record
			mergedRecords = append(mergedRecords, record)
		}
	}

	return mergedRecords
}

// Creates a unique key for a DNSRecord based on its type and hostname
func recordKeyForMerging(record DNSRecord) string {

	var key string
	if record.ARecord != nil {
		key = fmt.Sprintf("A-%s", record.ARecord.Name)
	} else if record.AAAARecord != nil {
		key = fmt.Sprintf("AAAA-%s", record.AAAARecord.Name)
	} else if record.TXTRecord != nil {
		key = fmt.Sprintf("TXT-%s", record.TXTRecord.Name)
	} else if record.CNAMERecord != nil {
		key = fmt.Sprintf("CNAME-%s", record.CNAMERecord.Name)
	} else if record.NSRecord != nil {
		key = fmt.Sprintf("NS-%s", record.NSRecord.Name)
	} else if record.SRVRecord != nil {
		key = fmt.Sprintf("SRV-%s", record.SRVRecord.Name)
	} // Add other record types as needed
	return key
}

// Merges values from one DNSRecord into another based on type
func mergeRecordValues(existingRecord, newRecord *DNSRecord) {
	// Example for A records; extend logic for other types as necessary
	if existingRecord.ARecord != nil && newRecord.ARecord != nil {
		valueSet := make(map[string]bool)
		for _, value := range existingRecord.ARecord.Values {
			valueSet[value] = true
		}
		for _, value := range newRecord.ARecord.Values {
			if !valueSet[value] {
				existingRecord.ARecord.Values = append(existingRecord.ARecord.Values, value)
			}
		}
	}
	// Repeat for AAAA, TXT, etc., with appropriate adjustments
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

func processIncludeDirective(filePath, includeOrigin string, rootPath string) ([]DNSRecord, error) {

	includedRecords, _, err := ParseZoneFile(filePath, includeOrigin, true, rootPath)
	if err != nil {
		return nil, fmt.Errorf(ColorRed+"Error processing $INCLUDE %s: %v\n"+ColorReset, filePath, err)
	}

	return includedRecords, nil
}

func processIncludedZoneFile(zoneFilePath, outputFileName string, customOrigin string) {

	// Parse the zone file
	_, zoneConfig, err := ParseZoneFile(zoneFilePath, customOrigin, false, "")
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

func sanitizeHostname(hostname, origin string) string {
	// Convert the hostname to lowercase
	hostname = strings.ToLower(hostname)

	// Remove any instances of ".."
	hostname = strings.ReplaceAll(hostname, "..", ".")

	// Ensure the origin is not duplicated at the end of the hostname
	dotOrigin := "." + strings.TrimPrefix(origin, ".")
	if strings.HasSuffix(hostname, dotOrigin+dotOrigin) {
		hostname = strings.TrimSuffix(hostname, dotOrigin)
	}

	// Allow alphanumeric, hyphens, periods, and underscore
	re := regexp.MustCompile(`[^a-zA-Z0-9\-\._]+`)
	sanitized := re.ReplaceAllString(hostname, "")

	// Ensure it does not start or end with a hyphen or period (common DNS rule)
	re = regexp.MustCompile(`(^[-\.]+|[-\.]+$)`)
	sanitized = re.ReplaceAllString(sanitized, "")

	// Pattern allows hostnames according to specified rules
	pattern := `^([*]|[a-zA-Z0-9-/_]{1,63})([.][a-zA-Z0-9-/_]{1,63})*$`
	re2 := regexp.MustCompile(pattern)

	if !re2.MatchString(sanitized) {
		fmt.Printf("%sWarning:%s Hostname may not meet requirement for XC DNS: %s %s\n", ColorRed, ColorYellow, sanitized, ColorReset)
	}

	// Remove any trailing dot to ensure a clean hostname as the final step
	sanitized = strings.TrimSuffix(sanitized, ".")

	return sanitized
}

func removeConflictingCNAMEs(records []DNSRecord, origin string, includeOrigin string) ([]DNSRecord, error) {
	aRecordHostnames := make(map[string]bool)
	filteredRecords := make([]DNSRecord, 0)

	// First, collect all A record hostnames
	for _, record := range records {
		if record.ARecord != nil {
			aRecordHostnames[record.ARecord.Name] = true
		}
	}

	// Now, filter out CNAME records that conflict with A record hostnames
	for _, record := range records {
		if record.CNAMERecord != nil {
			if _, exists := aRecordHostnames[record.CNAMERecord.Name]; exists {
				// Log an error and skip adding this CNAME record
				fmt.Printf(ColorRed+"Error:"+ColorYellow+" CNAME record for hostname '%s.%s' removed due to conflict with an A record: %s\n"+ColorReset, record.CNAMERecord.Name, includeOrigin, record.CNAMERecord.Value)
				//fmt.Printf("CNAME record name cannot be shared with other record types: A\n")
				continue
			}
		}
		// Add non-conflicting records to the filtered list
		filteredRecords = append(filteredRecords, record)
	}

	return filteredRecords, nil
}

func sanitizeValue(value string) string {
	//value = strings.ToLower(value)

	sanitized := strings.TrimSuffix(value, ".")

	return sanitized
}

// ensureFQDN checks if a given value is a proper FQDN. If not, it appends the origin.
func ensureFQDN(value, origin string) (string, bool) {
	// Simple pattern to match basic FQDN structure, without advanced assertions
	fqdnPattern := regexp.MustCompile(`^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$`)
	value = strings.TrimSuffix(value, ".") // Ensure no trailing dot for the validation

	isFQDN := fqdnPattern.MatchString(value)

	// Append origin if value is not an FQDN, origin is provided, and value does not already end with origin
	if !isFQDN && origin != "" && !strings.HasSuffix(value, origin) {
		value += "." + origin
	}

	// Remove any trailing dots from the final value
	value = strings.TrimSuffix(value, ".")

	if !isFQDN {
		//fmt.Printf("Value %s was not an FQDN.\n", value)
	}

	return value, isFQDN
}

func isHostnameValid(hostname string) bool {
	// Check if hostname ends with a trailing period
	if strings.HasSuffix(hostname, ".") {
		return false
	}

	// Check if the hostname is not all lowercase (indicating mixed case)
	if hostname != strings.ToLower(hostname) {
		return false
	}

	pattern := `^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`
	matched, _ := regexp.MatchString(pattern, hostname)
	return matched
}

func consolidateTXTRecords(records []DNSRecord) ([]DNSRecord, error) {
	// Initialize a map to hold consolidated TXT records by name
	consolidatedRecordsMap := make(map[string]*DNSRecord)

	// Other types of records can be directly appended to the final slice
	var finalRecords []DNSRecord

	for _, record := range records {
		if record.TXTRecord != nil && record.TXTRecord.Name == "" {
			// Handle TXT records without a hostname
			key := "TXT-no-hostname"
			if existingRecord, exists := consolidatedRecordsMap[key]; exists {
				// Check if appending this record would exceed the limit
				if len(existingRecord.TXTRecord.Values)+len(record.TXTRecord.Values) > 100 {
					// Log an error with all values that won't be included
					excessValues := record.TXTRecord.Values[100-len(existingRecord.TXTRecord.Values):]
					fmt.Printf(ColorRed+"Error: Exceeded TXT record values limit for records without a hostname. Excess values: %v%s\n", excessValues, ColorReset)
					// Only append values up to the limit
					existingRecord.TXTRecord.Values = append(existingRecord.TXTRecord.Values, record.TXTRecord.Values[:100-len(existingRecord.TXTRecord.Values)]...)
				} else {
					// Append values to the existing TXT record
					existingRecord.TXTRecord.Values = append(existingRecord.TXTRecord.Values, record.TXTRecord.Values...)
				}
			} else {
				// If it's the first record of its kind, add it to the map
				newRecord := record // Make a copy to avoid modifying the original
				consolidatedRecordsMap[key] = &newRecord
			}
		} else {
			// Directly append non-TXT records or TXT records with a hostname
			finalRecords = append(finalRecords, record)
		}
	}

	// Append consolidated TXT records without a hostname to the final records slice
	for _, record := range consolidatedRecordsMap {
		finalRecords = append(finalRecords, *record)
	}

	return finalRecords, nil
}

func ParseZoneFile(filePath string, customOrigin string, onlyRecords bool, bindFileRootPath string) ([]DNSRecord, *ZoneConfig, error) {

	fileDir := filepath.Clean(bindFileRootPath)

	//fmt.Println("Using root zone file directory:", fileDir)

	if !onlyRecords {
		if processedFiles[filePath] {
			fmt.Printf("Skipping already processed file: %s\n", filePath)
			return nil, nil, fmt.Errorf("file already processed: %s", filePath)
		}
		processedFiles[filePath] = true
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	const defaultTTLValue = 300          // Define a constant for the default TTL
	var defaultTTL int = defaultTTLValue // Use this variable to store the effective default TTL

	var lastTTL int
	var origin string
	var originalOrigin string
	var includeOrigin string
	var lastHostname string = "@" // Assume root by default for records without an explicit hostname
	//var lastRecordType string     // Flag for null hostnames to join into array
	var inSOARecord bool  // Flag to indicate if we're currently processing an SOA record
	var soaLines []string // Temporarily store SOA record lines for processing
	var records []DNSRecord
	var inZoneBlock bool // Flag to indicate we're currently processing a zone block for includes
	var zoneConfigLines []string

	var aDescription string = "" // include description for A records

	var zoneConfig *ZoneConfig

	if zoneConfig == nil {
		zoneConfig = &ZoneConfig{}
		zoneConfig.Metadata.Labels = make(map[string]string)
		zoneConfig.Metadata.Annotations = make(map[string]string)
		zoneConfig.Metadata.Description = "Zone Converted from BIND Zone File by MC Tool"

	}

	// Outside the parsing loop, prepare to collect NS / A records
	rootNSRecords := []string{}                     // For root-level NS records
	subdomainNSRecords := make(map[string][]string) // For subdomain-specific NS records

	rootNSSet := make(map[string]struct{})
	subdomainNSSets := make(map[string]map[string]struct{}) // A map of sets, one set per subdomain

	rootARecords := []string{}                     // For accumulating A record values by hostname
	subdomainARecords := make(map[string][]string) // For accumulating A record values by hostname

	rootAAAARecords := []string{}                     // For accumulating AAAA record values by hostname
	subdomainAAAARecords := make(map[string][]string) // For accumulating AAAA record values by hostname

	srvRecordsMap := make(map[string]*SRVRecord) // For accumulating SRV records values by hostname

	txtRecordsMap := make(map[string]*TXTRecordWithDesc) // For accumulating TXT records values

	cnameRecordsMap := make(map[string]*CNAMERecord)

	// Initialize with user-provided customOrigin if available
	if customOrigin != "" {
		origin = customOrigin
		originalOrigin = customOrigin // Treat the customOrigin as the original if provided
	}

	for scanner.Scan() {
		line := scanner.Text() // Use the original line with leading spaces for whitespace detection
		trimmedLine := strings.TrimSpace(line)

		// Skip comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, ";") {
			continue
		}

		// Handle $ORIGIN directive within the file only if customOrigin is not provided
		if strings.HasPrefix(trimmedLine, "$ORIGIN") {
			foundOrigin := strings.Fields(trimmedLine)[1]
			if origin == "" || origin == customOrigin { // Update origin only if not set by user
				origin = foundOrigin
				if originalOrigin == customOrigin { // Only update originalOrigin if not overridden by user
					originalOrigin = foundOrigin
				}
			}
			zoneConfig.Metadata.Name = origin
			continue
		}

		// Use customOrigin as the default if no $ORIGIN directive was found in the file
		if origin == "" {
			// Since customOrigin is also "", no origin has been specified or detected
			return nil, nil, fmt.Errorf("no $ORIGIN specified and none detected in the file")
		}

		// Special handling for $TTL
		if strings.HasPrefix(trimmedLine, "$TTL") {
			fields := strings.Fields(trimmedLine)
			if len(fields) > 1 {
				ttlValue, err := parseTTL(fields[1])
				if err != nil {
					fmt.Printf("Error parsing TTL value '%s': %v. Using default TTL: %d\n", fields[1], err, defaultTTLValue)
					defaultTTL = defaultTTLValue // Use the default TTL if parsing fails
				} else {
					defaultTTL = ttlValue // Update the default TTL with the parsed value
				}
			}
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

					processIncludedZoneFile(zoneFilePath, domainName+".json", origin)
				}
			}
		}

		var ttl int
		var err error
		var hostname, recordType string
		var values []string
		var recordValueStartIndex int = -1

		_ = values

		// Main parsing logic for other record types
		parts := strings.Fields(trimmedLine)

		// Detect whether the line starts with whitespace indicating continuation of previous record
		startsWithWhitespace := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")

		if startsWithWhitespace {
			if isInt(parts[0]) && !inZoneBlock {
				// This is a TTL at the start of a continuation line
				ttl, err = strconv.Atoi(parts[0])
				if err != nil || ttl <= 0 {
					ttl = defaultTTL
				}
				recordType = parts[1]
				values = parts[2:]
			} else {
				// Continuation line without a leading TTL, use last known values
				hostname = lastHostname
				ttl = lastTTL
				recordType = parts[0]
				values = parts[1:]
			}
		} else {
			if isInt(parts[0]) && !inZoneBlock {
				// Line starts with TTL
				ttl, err = strconv.Atoi(parts[0])
				if err != nil || ttl <= 0 {
					ttl = defaultTTL
				}
				recordType = parts[1]
				values = parts[2:]
			} else if !inZoneBlock && len(parts) > 2 {
				// Line starts with hostname or "IN"
				if parts[0] != "IN" {
					hostname = parts[0]
					ttl, err = strconv.Atoi(parts[1])
					if err != nil || ttl <= 0 {
						ttl = defaultTTL
					}
				} else {
					// "IN" indicates the record class, not a hostname; use the last known hostname
					hostname = lastHostname
					ttl, err = strconv.Atoi(parts[0])
					if err != nil || ttl <= 0 {
						ttl = defaultTTL
					}
				}
				recordType = parts[2]
				values = parts[3:]
			}
			lastHostname = hostname // Update the last known hostname

			// you cant trick me with your zero value!
			if ttl <= 0 {
				lastTTL = defaultTTL // Set to default TTL if ttl is zero or negative
			} else {
				lastTTL = ttl // Update the last known TTL if it's a positive value
			}

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
					hostname = strings.Replace(parts[0], " ", "", -1)
				}
				break
			}
		}

		// Adjust hostname based on includeOrigin if processing records only
		// Adjust hostname based on includeOrigin if processing records only
		if onlyRecords && includeOrigin != "" {
			if hostname == "@" || hostname == "" {
				hostname = includeOrigin
			} else {
				hostname = hostname + "." + includeOrigin
			}
		}

		var dnsRecord DNSRecord

		switch recordType {
		case "A":
			isRoot := hostname == "@" || hostname == "" || hostname == "IN"

			if !isRoot && hostname == "" {
				hostname = lastHostname // Use the last known valid hostname
			} else {
				if hostname == "" {
					hostname = "@"
				}
			}

			// Split the value to sanitize it and possibly capture the description
			valueParts := strings.SplitN(parts[recordValueStartIndex], ";", 2)
			sanitizedValue := strings.TrimSpace(valueParts[0]) // The actual A record value, sanitized
			if len(valueParts) > 1 {
				description := strings.TrimSpace(valueParts[1]) // Capture the description part
				aDescription = description
			}

			if isRoot {
				// For root-level records, append sanitizedValue directly
				rootARecords = append(rootARecords, sanitizedValue)
			} else {
				// For subdomain records, use lastValidHostname if hostname is not explicitly set
				subdomainARecords[hostname] = append(subdomainARecords[hostname], sanitizedValue)
			}
		case "NS":
			if len(parts) > recordValueStartIndex {
				nsValue := parts[recordValueStartIndex]
				var root bool

				if parts[0] == "@" || parts[0] == "" || isInt(parts[0]) || parts[0] == "IN" {
					root = true
				} else {
					hostname = parts[0]
					root = false
				}

				nsValue = sanitizeValue(nsValue)

				if root {
					// Check if value is already in the set for root NS records
					if _, exists := rootNSSet[nsValue]; !exists {
						rootNSSet[nsValue] = struct{}{}
						rootNSRecords = append(rootNSRecords, nsValue) // Append only if not exists
					}
				} else {
					// Initialize subdomain set if it doesn't exist
					if _, exists := subdomainNSSets[hostname]; !exists {
						subdomainNSSets[hostname] = make(map[string]struct{})
					}
					// Check if value is already in the set for this subdomain
					if _, exists := subdomainNSSets[hostname][nsValue]; !exists {
						subdomainNSSets[hostname][nsValue] = struct{}{}
						subdomainNSRecords[hostname] = append(subdomainNSRecords[hostname], nsValue) // Append only if not exists
					}
				}
			}
		case "CNAME":
			err := processCNAME(line, cnameRecordsMap, origin, customOrigin)
			if err != nil {
				fmt.Println("Error processing CNAME:", err)
			}
		case "SRV":
			if len(parts) >= 6 {
				priority, errPri := strconv.Atoi(parts[3])
				weight, errWei := strconv.Atoi(parts[4])
				port, errPort := strconv.Atoi(parts[5])
				target := parts[6] // Ensure this part exists or adapt accordingly

				if errPri != nil || errWei != nil || errPort != nil {
					//fmt.Println("Error parsing SRV record parts: <priority> <weight> <port> <target>", errPri, errWei, errPort, target)
					fmt.Printf(ColorRed+"Error Parsing SRV record - Priority: %d, Weight: %d, Port: %d, Target: %s\n"+ColorReset, priority, weight, port, target)

					continue // Skip this record on parsing error
				}

				target = sanitizeValue(target)

				srvValue := struct {
					Priority int    `json:"priority"`
					Weight   int    `json:"weight"`
					Port     int    `json:"port"`
					Target   string `json:"target"`
				}{
					Priority: priority,
					Weight:   weight,
					Port:     port,
					Target:   target,
				}

				// Construct the SRV record key to check if it exists in the map
				srvKey := hostname // Use hostname or construct a unique identifier for the SRV record

				// Check if this SRV record already exists in the map
				if existingRecord, exists := srvRecordsMap[srvKey]; exists {
					// SRV record exists, append new value to existing record's values slice
					existingRecord.Values = append(existingRecord.Values, srvValue)
				} else {
					// New SRV record, create it and add to map
					srvRecordsMap[srvKey] = &SRVRecord{
						Name: hostname,
						Values: []struct {
							Priority int    `json:"priority"`
							Weight   int    `json:"weight"`
							Port     int    `json:"port"`
							Target   string `json:"target"`
						}{srvValue},
					}
				}
			} else {
				partsAsString := strings.Join(parts, " ")
				fmt.Println("Insufficient parts to parse SRV record. Parsed values:", partsAsString)

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
				// First, extract the entire quoted string for the TXT value, including semicolons within quotes
				quotedValueRegex := regexp.MustCompile(`"([^"]+)"`)
				matches := quotedValueRegex.FindAllStringSubmatch(line, -1)
				var recordValues []string
				var description string

				for _, match := range matches {
					if len(match) > 1 {
						// Append each quoted string (without quotes) to recordValues
						recordValues = append(recordValues, match[1])
					}
				}

				// Concatenate all parts of the TXT record separated by a space
				recordValue := strings.Join(recordValues, " ")

				// Check the length of the concatenated recordValue
				if len(recordValue) >= 512 {
					fmt.Printf(ColorRed+"Warning: "+ColorYellow+"TXT record [%s] value too long (%d) and will not be included: %s%s\n", hostname, len(recordValue), recordValue, ColorReset)
					continue // Skip adding this record
				} else if len(recordValue) <= 0 {
					fmt.Printf(ColorRed+"Warning: "+ColorYellow+"TXT record [%s] value is null (%d) and will not be included: %s%s\n", hostname, len(recordValue), recordValue, ColorReset)
					continue
				}

				// Generate a key for each TXT record based on hostname and record value
				txtKey := fmt.Sprintf("%s-%s", hostname, recordValue)

				// Now, separate the description if any, which should be after a semicolon that's outside of quotes
				if lastQuoteEnd := quotedValueRegex.FindStringIndex(line); lastQuoteEnd != nil && len(line) > lastQuoteEnd[1] {
					// Find the first semicolon after the quoted TXT value
					descriptionStartIndex := strings.Index(line[lastQuoteEnd[1]:], ";")
					if descriptionStartIndex != -1 {
						// Adjust index relative to the entire line and not just the substring
						descriptionStartIndex += lastQuoteEnd[1]
						// Extract description, trim leading/trailing spaces
						description = strings.TrimSpace(line[descriptionStartIndex+1:])
					}
				}

				// Determine hostname and set to "" if specific conditions are met
				if len(parts) >= 3 && (parts[0] == "" || isInt(parts[0]) || parts[0] == "IN") && parts[1] == "TXT" {
					hostname = ""
				}

				// Check if this TXT record is already in the map
				if _, exists := txtRecordsMap[txtKey]; !exists {
					// If not, add it to the map
					txtRecordsMap[txtKey] = &TXTRecordWithDesc{
						TXTRecord: &TXTRecord{
							Name:   hostname,
							Values: []string{recordValue},
						},
						Description: description,
					}
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
				var root bool

				root = true

				if parts[0] == "@" || parts[0] == "" || isInt(parts[0]) {
					hostname = "@"
					root = true
				} else {
					hostname = parts[0]
					root = false
				}

				if root {
					rootAAAARecords = append(rootAAAARecords, parts[recordValueStartIndex])
				} else {
					subdomainAAAARecords[hostname] = append(subdomainAAAARecords[hostname], parts[recordValueStartIndex])
				}
			}
		}

		if strings.HasPrefix(trimmedLine, "$INCLUDE") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 2 {
				includeFilePath := filepath.Join(fileDir, parts[1]) // Construct the full path of the included file
				//includeFilePath := fileDir
				//includeOrigin = origin // Default to using the current origin if not specified in $INCLUDE

				if len(parts) >= 3 {
					includeOrigin = parts[2] // Override with specific origin if provided
				} else if len(parts) < 3 {
					includeOrigin = origin
				}

				includedRecords, err := processIncludeDirective(includeFilePath, includeOrigin, bindFileRootPath)
				if err != nil {
					fmt.Printf(ColorRed+"Error processing $INCLUDE %s %s: %v\n"+ColorReset, line, includeFilePath, err)
				}

				records = append(records, includedRecords...)

			}
			continue
		}
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
			TTL:         86400, // Or determine TTL differently
			ARecord:     &ARecord{Values: rootARecords},
			Description: aDescription,
		}
		records = append(records, aRecord)
	}

	// After parsing, create DNSRecord entries for the A records similarly to NS records
	for hostname, values := range subdomainARecords {
		aRecord := DNSRecord{
			TTL:         defaultTTL,
			ARecord:     &ARecord{Name: hostname, Values: values},
			Description: aDescription,
		}
		records = append(records, aRecord)
	}

	if len(rootAAAARecords) > 0 {
		aaaaRecord := DNSRecord{
			TTL:        defaultTTL,
			AAAARecord: &AAAARecord{Values: rootAAAARecords},
		}
		records = append(records, aaaaRecord)
	}

	for hostname, values := range subdomainAAAARecords {
		aaaaRecord := DNSRecord{
			TTL:        defaultTTL,
			AAAARecord: &AAAARecord{Name: hostname, Values: values},
		}
		records = append(records, aaaaRecord)
	}

	for _, srvRecord := range srvRecordsMap {
		srvRecords := DNSRecord{
			TTL:       defaultTTL,
			SRVRecord: srvRecord,
		}

		records = append(records, srvRecords)
	}

	// Convert map entries back to DNSRecord and append them to records slice
	for _, recordWithDesc := range txtRecordsMap {
		txtRecord := DNSRecord{
			TTL: defaultTTL,
			TXTRecord: &TXTRecord{
				Name:   recordWithDesc.TXTRecord.Name,
				Values: recordWithDesc.TXTRecord.Values,
			},
			Description: recordWithDesc.Description,
		}

		records = append(records, txtRecord)
	}

	for _, cnameRecords := range cnameRecordsMap {
		cnameRecord := DNSRecord{
			TTL: defaultTTL,
			CNAMERecord: &CNAMERecord{
				Name:  cnameRecords.Name,
				Value: cnameRecords.Value,
			},
		}
		records = append(records, cnameRecord)
	}

	// Remove conflicting CNAME records first
	records, err = removeConflictingCNAMEs(records, customOrigin, includeOrigin)
	if err != nil {
		fmt.Printf("I hit a snag...")
	}

	// Remove complete duplicates
	records = deduplicateAndMergeDNSRecords(records)

	// Consolidate TXT records without a hostname, handling any potential errors
	records, err = consolidateTXTRecords(records)
	if err != nil {
		// Handle the error appropriately, perhaps by logging it or even stopping execution
		fmt.Printf("Error consolidating TXT records: %v\n", err)
		//return // or continue
	}

	zoneConfig.Metadata.Name = origin
	//zoneConfig.Spec.Primary.DefaultRRSetGroup = records
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
		return nil, nil, err
	}

	// doing a final check on SOA values
	if zoneConfig.Spec.Primary.SOAParameters.Refresh <= 3600 {
		zoneConfig.Spec.Primary.SOAParameters.Refresh = 86400 // Set to a default refresh value
	}
	if zoneConfig.Spec.Primary.SOAParameters.Retry <= 7200 {
		zoneConfig.Spec.Primary.SOAParameters.Retry = 7200 // Set to a default retry value
	}
	if zoneConfig.Spec.Primary.SOAParameters.Expire <= 3600000 {
		zoneConfig.Spec.Primary.SOAParameters.Expire = 3600000 // Set to a default expire value
	}
	if zoneConfig.Spec.Primary.SOAParameters.NegativeTTL <= 1801 {
		zoneConfig.Spec.Primary.SOAParameters.NegativeTTL = 1801 // Set to a default negative TTL value
	}
	if zoneConfig.Spec.Primary.SOAParameters.TTL <= 300 {
		zoneConfig.Spec.Primary.SOAParameters.TTL = 300 // Set to a default TTL value
	}

	// Return based on the onlyRecords flag.
	if onlyRecords {
		return records, nil, nil // Return only records and no error.
	} else {
		return nil, zoneConfig, nil // Return the full ZoneConfig and no error.
	}
}

func main() {

	// Define command-line flags
	inputFilePath := flag.String("input", "", "Path to the input zone file")
	outputFilePath := flag.String("output", "", "Path to the output JSON file")
	bindFileRootPath := flag.String("root", ".", "BIND file root path for resolving file references")
	customOrigin := flag.String("origin", "", "Optional origin to override $ORIGIN in the zone file")

	// Parse the command-line flags
	flag.Parse()

	// Check required arguments (input and output paths must be provided)
	if *inputFilePath == "" || *outputFilePath == "" {
		fmt.Println("Usage: program -input <input_zone_file> -output <output_json_file> [-root <bind_file_root_path>] [-origin <optional_origin>]")
		flag.PrintDefaults()
		return
	}

	fullPath := *bindFileRootPath

	// Check if the path starts with "./"
	if strings.HasPrefix(fullPath, "./") {
		// Convert to an absolute path. Note the use of = instead of :=
		var err error
		fullPath, err = filepath.Abs(fullPath)
		if err != nil {
			fmt.Printf("Error getting absolute path: %v\n", err)
			return // Make sure to return or handle the error appropriately
		}
	}

	// Parse the zone file with the optional origin and BIND file root path
	_, zoneConfig, err := ParseZoneFile(*inputFilePath, *customOrigin, false, fullPath)
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
	err = os.WriteFile(*outputFilePath, jsonBytes, 0644)
	if err != nil {
		fmt.Printf("Error writing to output file: %v\n", err)
		return
	}

	fmt.Printf("Successfully wrote JSON output to %s\n", *outputFilePath)
}
