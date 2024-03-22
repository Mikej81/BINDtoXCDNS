# BIND to XC-DNS Converter

This tool is designed to convert BIND zone files into the XC JSON format, making it easier to work with different DNS management systems. It currently supports NS, MX, A, AAAA, TXT, CNAME, and SRV record types.

## Features

Converts BIND zone file records (NS, MX, A, AAAA, TXT, CNAME, SRV) into XC DNS JSON format.
Allows specifying a root path for zone files, useful for $INCLUDE directives in BIND files.
Provides an option to override the $ORIGIN directive with a custom domain name.

## Usage

To use the BIND to XC-DNS converter, run the following command with the necessary flags:

```bash
bindtoxcdns -input /path/to/bind/file -output /path/to/output/json [optional flags]
```

### Flags

- input (required): Specifies the path to the BIND zone file you wish to convert.
- output (required): Specifies the path where the resulting XC DNS JSON file should be saved.
- root (optional): Sets the root directory path for any relative file paths encountered in $INCLUDE directives within the BIND zone file. This is useful when your BIND configuration is spread across multiple files.
- origin (optional): Overrides the $ORIGIN directive found in the BIND zone file. Use this if you need to specify a different domain name than the one defined in the zone file.

## Examples

### Basic Conversion

Convert a single BIND zone file to XC DNS JSON format:

```bash
bindtoxcdns -input /path/to/example.zone -output /path/to/example.json
```

### Conversion with Root Path

Convert a BIND zone file that includes other files, specifying the root directory for included files:

```bash
bindtoxcdns -input /path/to/main.zone -output /path/to/output.json -root /path/to/zone/files
```

### Conversion with Origin Override

Convert a BIND zone file and override the $ORIGIN directive with a custom domain name:

```bash
bindtoxcdns -input /path/to/example.zone -output /path/to/example.json -origin custom.example.com
```

This command processes example.zone, replaces the origin with custom.example.com, and saves the converted JSON to example.json.

## Contributing

Contributions to improve the BIND to XC-DNS converter are welcome. Please feel free to submit issues and pull requests with enhancements, bug fixes, or additional features.
