#!/bin/sh
set -e

# Directory for rules in the host
RULES_DIR="./coraza/rules"
TEMP_DIR="./temp_crs"
CRS_VERSION="3.3.5"

echo "Updating Core Rule Set to version $CRS_VERSION..."

# Create temp directory
mkdir -p $TEMP_DIR

# Download latest CRS
curl -s -L "https://github.com/coreruleset/coreruleset/archive/refs/tags/v$CRS_VERSION.tar.gz" -o $TEMP_DIR/crs.tar.gz

# Extract only the rules
mkdir -p $TEMP_DIR/extracted
tar -xzf $TEMP_DIR/crs.tar.gz -C $TEMP_DIR/extracted --strip-components=1

# Create backup of current rules if they exist
if [ -d "$RULES_DIR" ] && [ "$(ls -A $RULES_DIR 2>/dev/null)" ]; then
    BACKUP_DIR="./coraza/rules_backup_$(date +%Y%m%d_%H%M%S)"
    echo "Creating backup of current rules to $BACKUP_DIR"
    mkdir -p $BACKUP_DIR
    cp -r $RULES_DIR/* $BACKUP_DIR/
fi

# Process and copy rules
echo "Processing and copying rules to $RULES_DIR"
mkdir -p $RULES_DIR

# Copy the CRS setup file first
if [ -f "$TEMP_DIR/extracted/crs-setup.conf.example" ]; then
    echo "Copying and configuring crs-setup.conf..."
    cp "$TEMP_DIR/extracted/crs-setup.conf.example" "$RULES_DIR/crs-setup.conf"
fi

# Process and copy rules from the extracted archive - only taking the core rules
for file in $TEMP_DIR/extracted/rules/*.conf; do
    base_filename=$(basename "$file")
    
    # Skip exclusion rules and problematic rules
    if [[ "$base_filename" == *"EXCLUSION"* ]] || [[ "$base_filename" == "REQUEST-910-IP-REPUTATION.conf" ]]; then
        echo "Skipping problematic rule file: $base_filename"
        continue
    fi
    
    echo "Copying rule file: $base_filename"
    cp "$file" "$RULES_DIR/$base_filename"
done

# Add a basic rule to ensure there's something functional
echo "Creating basic fallback rules..."
cat > "$RULES_DIR/basic-rules.conf" << EOF
# Basic WAF rules that will work with Coraza
SecRule REQUEST_URI "@contains /admin" "id:1000,phase:1,deny,status:403,msg:'Admin access blocked'"
SecRule ARGS "@contains SELECT FROM" "id:1001,phase:2,deny,status:403,msg:'SQL Injection attempt detected'" 
SecRule ARGS "@contains <script>" "id:1002,phase:2,deny,status:403,msg:'XSS attempt detected'"
SecRule REQUEST_URI "@contains ../etc/passwd" "id:1003,phase:1,deny,status:403,msg:'Path traversal attempt'"
SecRule REQUEST_URI "@contains cmd=" "id:1004,phase:1,deny,status:403,msg:'Command injection attempt'"
EOF

# Clean up
rm -rf $TEMP_DIR

echo "Done! Core Rule Set updated to version $CRS_VERSION"
echo "Restart your container with 'docker-compose restart coraza' to apply the changes"
