#!/bin/bash
# run_tests.sh — Run LogWise test suite with coverage report
# Usage: bash scripts/run_tests.sh

set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║       LogWise Test Runner            ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check dependencies
if ! python3 -c "import pytest" 2>/dev/null; then
  echo "Installing test dependencies..."
  pip install pytest pytest-cov --quiet
fi

cd "$(dirname "$0")/.."

echo "Running 40 tests across 5 modules..."
echo ""

python3 -m pytest tests/test_logwise.py \
  -v \
  --tb=short \
  --cov=src \
  --cov-report=term-missing \
  --cov-report=html:htmlcov \
  -q

echo ""
echo "Coverage report saved to: htmlcov/index.html"
echo ""
