#!/bin/bash

# VulnaraX Core API Startup Script
echo "🚀 Starting VulnaraX Core API..."
echo "📍 Service will be available at: http://localhost:8002"
echo "📚 API Documentation: http://localhost:8002/docs"
echo ""

# Check for NVD API key
if [ -z "$NVD_API_KEY" ]; then
    echo "⚠️  Warning: NVD_API_KEY environment variable not set"
    echo "📝 Get your API key from: https://nvd.nist.gov/developers/request-an-api-key"
    echo "🔧 Set it with: export NVD_API_KEY='your-key-here'"
    echo "⚡ Running with reduced rate limits"
    echo ""
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "⚠️  No virtual environment found. Creating one..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Start the FastAPI server with production settings
echo "🌟 Starting FastAPI server on port 8002..."
echo "⚡ Production mode: Async scanning with rate limiting"
echo "🔥 Concurrent scans: Up to 40 simultaneous requests"
echo ""

# For production, use multiple workers
uvicorn main:app --host 0.0.0.0 --port 8002 --workers 4 --reload