#!/bin/sh
set -e

CRS_REPO="https://github.com/coreruleset/coreruleset.git"
RULES_DIR="/etc/coraza/rules"
CRS_TMP_DIR="/tmp/crs-rules"

echo "Starting CRS update process..."

# Ensure directories exist
mkdir -p "${RULES_DIR}"
mkdir -p "${CRS_TMP_DIR}"

# Clone or update CRS repository
if [ -d "${CRS_TMP_DIR}/.git" ]; then
    echo "Updating existing CRS repository..."
    cd "${CRS_TMP_DIR}"
    git pull origin main
else
    echo "Cloning CRS repository..."
    git clone --depth 1 "${CRS_REPO}" "${CRS_TMP_DIR}"
fi

# Sync rules directory
echo "Syncing rules..."
cd "${CRS_TMP_DIR}"

# First clean up the rules directory
rm -f "${RULES_DIR}"/*.conf "${RULES_DIR}"/*.data

# Copy rules from the correct path
echo "Copying rules from ${CRS_TMP_DIR}/rules..."
cp -fv rules/*.conf "${RULES_DIR}/" 2>/dev/null || true
cp -fv rules/*.data "${RULES_DIR}/" 2>/dev/null || true

# Handle example files
for f in rules/*.example; do
    if [ -f "$f" ]; then
        basename=$(basename "$f" .example)
        if [ ! -f "${RULES_DIR}/${basename}" ]; then
            cp -v "$f" "${RULES_DIR}/${basename}"
        fi
    fi
done

# Copy CRS setup configuration
cp "${CRS_TMP_DIR}/crs-setup.conf.example" "${RULES_DIR}/crs-setup.conf"

# Create empty exclusion files (required by CRS)
touch "${RULES_DIR}/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
touch "${RULES_DIR}/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"

# List copied files for verification
echo "Files in rules directory:"
ls -la "${RULES_DIR}"

echo "CRS rules updated successfully"
