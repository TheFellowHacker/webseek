#!/bin/bash

# Define colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
RESET=$(tput sgr0)  # Reset color

# Function to display script usage
display_usage() {
    echo -e "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help               Display this help message"
    echo "  -d, --domain <name>      Specify a single domain name with https://example.com format"
    echo "  -sL, --subdomains-list   Specify a file containing a list of subdomains"
    echo "  -o, --output <directory> Specify output directory (default: webseek)"
    exit 1
}

# Default variables
DEFAULT_DIR="webseek"
DOMAIN=""
SUBDOMAINS_FILE=""
OUTPUT_DIR=""

# Parse command line options
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -h|--help)
            display_usage
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -sL|--subdomains-list)
            SUBDOMAINS_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            display_usage
            ;;
    esac
done

# Validate input parameters
if [ -z "$DOMAIN" ] && [ -z "$SUBDOMAINS_FILE" ]; then
    display_usage
elif [ ! -z "$DOMAIN" ] && [ ! -z "$SUBDOMAINS_FILE" ]; then
    echo "[!] Specify either -d or -sL, not both."
    exit 1
elif [ ! -z "$SUBDOMAINS_FILE" ] && [ ! -f "$SUBDOMAINS_FILE" ]; then
    echo "[!] Subdomains file not found: $SUBDOMAINS_FILE"
    exit 1
fi

# Function to create directories if they don't exist
create_directory() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        if [ $? -ne 0 ]; then
            echo "[!] Failed to create directory: $dir"
            exit 1
        fi
    fi
}

# Check if -o is specified and set result_dir accordingly
if [ -n "$OUTPUT_DIR" ]; then
    result_dir="$DEFAULT_DIR/$OUTPUT_DIR"
else
    # Check if the URL starts with https:// and extract domain
    if [ -n "$DOMAIN" ]; then
        # Check if the URL starts with https://
        if [[ ! "$DOMAIN" =~ ^https:// ]]; then
            echo "[!] URL must start with https://"
            exit 1
        fi

        # Extract domain from URL without changing DOMAIN value
        extracted_domain=$(echo "$DOMAIN" | grep -oP '^https:\/\/\K[^\/]+')
        
        # Check if the domain extracted is empty
        if [ -z "$extracted_domain" ]; then
            echo "[!] Invalid domain format. Use https://example.com"
            exit 1
        fi

        result_dir="$DEFAULT_DIR/$extracted_domain"
    elif [ -n "$SUBDOMAINS_FILE" ]; then
        filename=$(basename -- "$SUBDOMAINS_FILE")
        filename_no_ext="${filename%.*}"
        result_dir="$DEFAULT_DIR/$filename_no_ext"
    else
        echo "Neither -d nor -sL option specified."
        exit 1
    fi
fi


# Create output directories
create_directory "$result_dir"
create_directory "$result_dir/URLS"
create_directory "$result_dir/parameters"
create_directory "$result_dir/js"
create_directory "$result_dir/URLS/unfurl_output"
create_directory "$result_dir/URLS/patterns"

# Function to check if a command succeeded
check_command() {
    if [ $? -ne 0 ]; then
        echo "[!] Error occurred during: $1"
        echo "[!] Details: $2"
        exit 1
    fi
}

# Logging function
log() {
    local log_file="$result_dir/webseek.log"
    local timestamp=$(date +"%Y-%m-%d %T")
    echo "[$timestamp] $1" >> "$log_file"
}

# Display banner
echo ""
echo -e "${RED}              _     ${RESET}""               _    "
echo -e "${RED}__      _____| |__  ${RESET}"" ___  ___  ___| | __"
echo -e "${RED}\ \ /\ / / _ \ '_ \ ${RESET}""/ __|/ _ \/ _ \ |/ /"
echo -e "${RED} \ V  V /  __/ |_) |${RESET}""\__ \  __/  __/   < "
echo -e "${RED}  \_/\_/ \___|_.__/ ${RESET}""|___/\___|\___|_|\_\ "
echo ""
echo -e "${YELLOW}      Created with <3 by 7h47-f3ll0w-h4ck3r     ${RESET}"
echo ""

# Tool functions for URL scanning and parameter discovery

# Run gospider
run_gospider() {
    local url="$1"
    echo "[*] Running gospider for: ${CYAN}$url${RESET}"
    gospider -s "$url" --js -t 20 -d 2 --sitemap --robots -w -r | grep -oP '(http|https)://[^ ]+' >> "$result_dir/URLS/gospider_urls.txt"
    log "Gospider scan completed"
    check_command "gospider for $url" ""
}

# Run waybackurls
run_waybackurls() {
    local url="$1"
    echo "[*] Running waybackurls for: ${CYAN}$url${RESET}"
    echo "$url" | waybackurls >> "$result_dir/URLS/waybackurls_urls.txt"
    if [ $? -ne 0 ]; then
        echo "[!] Error fetching URL with waybackurls for $url. Check waybackurls_error.log for details."
        exit 1
    fi
    log "waybackurls scan completed"
   }

# Run hakrawler
run_hakrawler() {
    local url="$1"
    echo "[*] Running hakrawler for: ${CYAN}$url${RESET}"
    echo "$url" | hakrawler -subs -d 2 -t 10 >> "$result_dir/URLS/hakrawler_urls.txt"
    check_command "hakrawler for $url" ""
    log "Scan with hakrawler completed"
}

# Run gau
run_gau() {
    local url="$1"
    echo "[*] Running gau for: ${CYAN}$url${RESET}"
    gau --providers wayback,otx,commoncrawl,urlscan "$url" --threads 50 --subs | grep -oP '(http|https)://[^ ]+' >> "$result_dir/URLS/gau_urls.txt"
    check_command "gau for $url" ""
    log "Scan with gau completed"
}

# Run waymore
run_waymore() {
    local url="$1"
    echo "[*] Running waymore for: ${CYAN}$url${RESET}"
    waymore -i "$url" -mode U -oU "$result_dir/URLS/waymore_urls.txt" > /dev/null 2>&1
    check_command "waymore for $url" ""
    log "waymore scan completed"
}

# Run katana (both passive and active scans)
run_katana() {
    local url="$1"
    echo "[*] Performing passive scan with Katana for: ${CYAN}$url${RESET}"
    katana -u "$url" -ps -silent -pss waybackarchive,commoncrawl,alienvault -o "$result_dir/URLS/katana_passive_urls.txt" > /dev/null 2>&1
    check_command "Katana passive for $url" ""
    log "Passive scan with Katana completed"

    echo "[*] Performing active scan with Katana for: ${CYAN}$url${RESET}"
    katana -u "$url" -duc -silent -nc -jc -kf -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -aff -o "$result_dir/URLS/katana_active_urls.txt" > /dev/null 2>&1
    check_command "Katana active for $url" ""
    log "Active scan with Katana completed"
}

# Function to scan for URLs
scan_urls() {
    local target="$1" 
    run_gospider "$target" &
    run_waybackurls "$target" &
    run_hakrawler "$target" &
    run_gau "$target" &
    run_waymore "$target" &
    run_katana "$target" 
}

# Parameter Discovery
# Paramspider function
run_paramspider() {
    local url="$1"
    # Extract domain from URL without changing DOMAIN value
    domain=$(echo "$url" | grep -oP '^https:\/\/\K[^\/]+')
    echo "[*] Running Paramspider for: ${CYAN}$domain${RESET}"
    paramspider -d "$domain" >> "$result_dir/parameters/paramspider_parameters.txt"  
    check_command "ParamSpider" "ParamSpider parameters extraction"
    log "Extracted parameters with ParamSpider"
}

# Run Parameth
run_parameth() {
    local url="$1"
    echo "[*] Running Parameth for: ${CYAN}$url${RESET}"
    parameth.py -u "$url" -p medium.txt -o "$result_dir/parameters/parameth_unfiltered_parameters.txt" > /dev/null 2>&1 
    
  if [ -n "$(find "$result_dir/parameters" -name 'parameth_unfiltered_parameters.txt' 2>/dev/null)" ]; then
    grep -o 'http[^ ]*' "$result_dir/parameters/parameth_unfiltered_parameters.txt" > "$result_dir/parameters/parameth_parameters.txt"
    rm "$result_dir/parameters/parameth_unfiltered_parameters.txt"
  fi
    check_command "Parameth for $url" ""
    log "Parameth scan completed"
}

# Run roboxtractor
run_roboxtractor() {
    local url="$1"
    echo "[*] Running roboxtractor for: ${CYAN}$url${RESET}"
    echo "$url" | roboxtractor -m 1 -wb -s > "$result_dir/parameters/roboxtractor_parameters.txt"
    check_command "roboxtractor for $url" ""
    log "Robots.txt analysis with roboxtractor completed"
}

# Run github-endpoints
run_github_endpoints() {
    local url="$1"
    # Extract domain from URL without changing DOMAIN value
    domain=$(echo "$url" | grep -oP '^https:\/\/\K[^\/]+')
    echo "[*] Running github-endpoints for: ${CYAN}$domain${RESET}"
    github-endpoints -d "$domain" -t "token.txt" -o "$result_dir/parameters/github-endpoints.txt" > /dev/null 2>&1
    check_command "github-endpoints for $url" ""
    log "Scan with github-endpoints completed"
}

# Function to discover parameters
discover_parameters() {
    local target="$1"
    # Run tools in parallel where possible
    run_paramspider "$target" &
    run_parameth "$target" &
    run_roboxtractor "$target" &
    run_github_endpoints "$target" 
}

# JS Enumeration Tools

# Run LinkFinder
run_linkfinder() {
    local url="$1"
    echo "[*] Running LinkFinder for: ${CYAN}$url${RESET}"
    linkfinder.py -i "$url" -d | grep ".js$"  >> "$result_dir/js/linkfinder_unfiltered_js.txt"
        
  if [ -n "$(find "$result_dir/js" -name 'linkfinder_unfiltered_js.txt' 2>/dev/null)" ]; then
    grep -E 'Running against: https?://[^ ]+' "$result_dir/js/linkfinder_unfiltered_js.txt" | sed 's/Running against: //g' > "$result_dir/js/linkfinder_js.txt"
    rm "$result_dir/js/linkfinder_unfiltered_js.txt"
  fi
    check_command "LinkFinder for $url" ""
    log "Scanned JS files with LinkFinder"
}

# JavaScript enumeration with subjs
run_subjs() {
    local url="$1"
    echo "[*] Running subjs for: ${CYAN}$url${RESET}"
    echo "$url" | subjs >> "$result_dir/js/subjs_js.txt"
    check_command "subjs for $url" ""
    log "JavaScript enumeration with subjs completed"
}

# JavaScript enumeration with katana
run_katana_js() {
    local url="$1"
    echo "[*] Running katana for JS enumeration: ${CYAN}$url${RESET}"
    katana -u "$url" -silent -js-crawl -d 5 -o "$result_dir/js/katana_js.txt" > /dev/null 2>&1
    check_command "katana for JS $url" ""
    log "JavaScript enumeration with katana completed"
}

# Function to enumerate JavaScript files
enumerate_js() {
    local target="$1"
    # Run tools in parallel where possible
    run_linkfinder "$target" &
    run_subjs "$target" &
    run_katana_js "$target" 
}

# Scan URLs if DOMAIN is specified
if [ -n "$DOMAIN" ]; then
    scan_urls "$DOMAIN" 
    discover_parameters "$DOMAIN" 
    enumerate_js "$DOMAIN" 
fi

# Scan subdomains if SUBDOMAINS_FILE is specified
if [ -n "$SUBDOMAINS_FILE" ]; then
    while IFS= read -r subdomain; do
        scan_urls "$subdomain" 
        discover_parameters "$subdomain" 
        enumerate_js "$subdomain"
    done < "$SUBDOMAINS_FILE"
fi

# Check if URL files exist before concatenation
if [ -n "$(find "$result_dir/URLS" -name '*_urls.txt' 2>/dev/null)" ]; then
    # Remove duplicate URLs
    echo "[*] Removing duplicate URLs"
    cat "$result_dir/URLS/"*.txt | sort -u > "$result_dir/URLS/unique_urls.txt"
    log "Removed duplicate URLs"
   
    # Search for sensitive patterns
    echo -e "${YELLOW}[*] Searching for sensitive patterns...${RESET}"
    grep -Ei 'password=|admin=|user=|login=|email=' "$result_dir/URLS/unique_urls.txt" > "$result_dir/URLS/patterns/sensitive_patterns.txt"
    check_command "grep for sensitive patterns" "grep for sensitive patterns"
    log "Searched for sensitive patterns"

    #Normalize urls
    echo "${WHITE}[*] Normalizing URLs with uro${RESET}"
    grep -E '^https?://([a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:[0-9]{1,5})?(/.*)?)?$' $result_dir/URLS/unique_urls.txt | uro > $result_dir/URLS/normalized_urls.txt
else
    echo "[!] No URL files found in $result_dir/URLS/"
fi

# Check if parameter files exist before concatenation
if [ -n "$(find "$result_dir/parameters" -name '*_parameters.txt' 2>/dev/null)" ]; then
    echo "${WHITE}[*] Concatenating parameter files into parameters.txt${RESET}"
    cat $result_dir/parameters/*_parameters.txt > $result_dir/parameters/parameters.txt

    echo "${WHITE}[*] Filtering fuzzing endpoints${RESET}"
    grep -Eo '([?&][a-zA-Z0-9_-]+=[a-zA-Z0-9_-]*)' $result_dir/parameters/parameters.txt > $result_dir/parameters/fuzzing_endpoints.txt
else
    echo "[!] No parameter files found in $result_dir/parameters/"
fi

# Check if urls.txt exists before running subjs
if [ -f "$result_dir/URLS/unique_urls.txt" ]; then
    echo "[*] Scanning unique_urls.txt with ${RED}subjs${RESET}"
    cat $result_dir/URLS/unique_urls.txt | subjs > $result_dir/js/subjs_on_urls_js.txt 
    log "subjs scan on unique_urls.txt completed"
else
    echo "[!] unique_urls.txt not found in $result_dir/URLS/"
    log "[!] ${RED}unique_urls.txt not found in $result_dir/URLS/ ${RESET}"
fi

# Check if JS files exist before concatenation and further processing
if [ -n "$(find "$result_dir/js" -name '*_js.txt' 2>/dev/null)" ]; then
    echo "${WHITE}[*] Concatenating JS files into js.txt${RESET}"
    cat $result_dir/js/*_js.txt > $result_dir/js/js.txt

    echo "${WHITE}[*] Performing subjs on ${RED}js.txt${RESET}"
    cat $result_dir/js/js.txt | subjs -t 10 > $result_dir/js/subjs_on_all_js.txt 

    echo "${WHITE}[*] Generating final all_js.txt...${RESET}"
    cat $result_dir/js/*js.txt | sort -u > $result_dir/js/all_js.txt

    echo "[*] Finding secrets with ${RED}mantra...${RESET}"
    cat "$result_dir/js/all_js.txt" | grep ".js$" | mantra > $result_dir/js/mantra.txt 2>/dev/null
    log "Scan with mantra Completed"

    echo "[*] Finding secrets with SecretFinder for: ${RED}all_js.txt ...${RESET}"
    secretfinder -i $result_dir/js/all_js.txt -o cli >> "$result_dir/js/secretfinder.txt"
    log "Scanned for secrets with secretfinder"
else
    echo "[!] No JS files found in $result_dir/js/"
    log "[!] ${RED}No JS files found in $result_dir/js/ ${RESET}"
fi

# Check if urls.txt exists before running unfurl
if [ -f "$result_dir/URLS/unique_urls.txt" ]; then
    echo "${WHITE}[*] Generating wordlist with unfurl${RESET}"
    cat $result_dir/URLS/unique_urls.txt | unfurl -u paths > $result_dir/URLS/unfurl_output/paths.txt
    cat $result_dir/URLS/unique_urls.txt | unfurl -u keys > $result_dir/URLS/unfurl_output/keys.txt
    cat $result_dir/URLS/unique_urls.txt | unfurl -u keypairs > $result_dir/URLS/unfurl_output/key-pairs.txt
    cat $result_dir/URLS/unique_urls.txt | unfurl -u values > $result_dir/URLS/unfurl_output/values.txt
    cat $result_dir/URLS/unique_urls.txt | unfurl -u json > $result_dir/URLS/unfurl_output/json.txt

    cat $result_dir/URLS/unfurl_output/* > $result_dir/URLS/unfurl.txt

    echo "${WHITE}[*] Performing gf patterns${RESET}"
    gf xss $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/xss.txt
    gf sqli $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/sqli.txt
    gf ssrf $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/ssrf.txt
    gf idor $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/idor.txt
    gf lfi $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/lfi.txt
    gf redirect $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/redirect.txt
    gf ssti $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/ssti.txt
    gf upload-fields $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/upload-fields.txt
    gf takeovers $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/takeovers.txt
    gf img-traversal $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/img-traversal.txt
    gf cors $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/cors.txt
    gf http-auth $result_dir/URLS/unique_urls.txt > $result_dir/URLS/patterns/http-auth.txt
else
    echo "[!] Unfurl - unique_urls.txt not found in $result_dir/URLS/"
    log "[!] ${RED}Unfurl - unique_urls.txt not found in $result_dir/URLS/ ${RESET}"
fi

echo "[*] Content discovery completed"
log "${YELLOW}Content discovery completed${RESET}"
