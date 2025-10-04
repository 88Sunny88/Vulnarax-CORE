#!/bin/bash

# Test script for VulnaraX API cache management endpoints

echo "🚀 Starting VulnaraX API integration test..."

# Start the server in background
cd /Users/alexandervidenov/Desktop/Vulnarax-core
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 5

# Test 1: Health check
echo "🔍 Testing health endpoint..."
curl -s -X GET "http://localhost:8000/health" | python3 -m json.tool
echo ""

# Test 2: Initial cache stats (should be empty or from previous tests)
echo "📊 Testing initial cache stats..."
curl -s -X GET "http://localhost:8000/cache/stats" | python3 -m json.tool
echo ""

# Test 3: Scan packages to populate cache
echo "🔍 Testing package scan (async)..."
curl -s -X POST "http://localhost:8000/scan/packages/async" \
  -H "Content-Type: application/json" \
  -d '{"packages": [{"name": "nginx", "version": "1.18.0"}]}' | python3 -m json.tool
echo ""

# Test 4: Check cache stats after scan
echo "📊 Testing cache stats after scan..."
curl -s -X GET "http://localhost:8000/cache/stats" | python3 -m json.tool
echo ""

# Test 5: Test cache cleanup
echo "🧹 Testing cache cleanup..."
curl -s -X POST "http://localhost:8000/cache/cleanup" | python3 -m json.tool
echo ""

# Test 6: Second scan to test cache performance
echo "⚡ Testing cached scan performance..."
time curl -s -X POST "http://localhost:8000/scan/packages/async" \
  -H "Content-Type: application/json" \
  -d '{"packages": [{"name": "nginx", "version": "1.18.0"}]}' > /dev/null
echo ""

# Test 7: Clear cache
echo "🗑️ Testing cache clear..."
curl -s -X DELETE "http://localhost:8000/cache/clear" | python3 -m json.tool
echo ""

# Test 8: Final cache stats (should be empty)
echo "📊 Testing final cache stats..."
curl -s -X GET "http://localhost:8000/cache/stats" | python3 -m json.tool
echo ""

# Cleanup
echo "🛑 Stopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo "✅ Integration test completed!"