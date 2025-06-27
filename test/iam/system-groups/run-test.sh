#!/bin/bash

# System Groups End-to-End Test Runner
# This script runs the Chainsaw test for system groups functionality

set -e

echo "🚀 Running System Groups End-to-End Test"
echo "=========================================="

# Check if chainsaw is available
if ! command -v chainsaw &> /dev/null; then
    echo "❌ Error: chainsaw command not found"
    echo "Please install chainsaw: https://kyverno.github.io/chainsaw/latest/"
    exit 1
fi

# Check if we're in the right directory
if [[ ! -f "chainsaw-test.yaml" ]]; then
    echo "❌ Error: chainsaw-test.yaml not found"
    echo "Please run this script from the test/iam/system-groups/ directory"
    exit 1
fi

echo "📋 Test Overview:"
echo "  - Create PolicyBinding with system:authenticated-users group (no UID)"
echo "  - Test authenticated user gets access"
echo "  - Test unauthenticated user is denied access"
echo "  - Test multiple authenticated users"
echo "  - Test different permissions (CREATE and GET)"
echo ""

echo "🏃 Running Chainsaw test..."
chainsaw test .

echo ""
echo "✅ System Groups test completed!"
echo ""
echo "📝 What was tested:"
echo "  ✓ PolicyBinding accepts system groups without UID validation"
echo "  ✓ Authorization webhooks process group contextual tuples"
echo "  ✓ Users with system:authenticated-users get appropriate access"
echo "  ✓ Users without system groups are denied access"
echo "  ✓ System groups work consistently across multiple users and permissions"
