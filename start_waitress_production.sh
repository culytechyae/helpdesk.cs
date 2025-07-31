#!/bin/bash

echo "========================================"
echo "Helpdesk Application - Production Server"
echo "========================================"
echo
echo "Starting Waitress Production Server..."
echo
echo "Configuration:"
echo "- Host: 0.0.0.0 (all interfaces)"
echo "- Port: 5000"
echo "- Threads: 4"
echo "- Connection Limit: 1000"
echo
echo "Access URLs:"
echo "- Local: http://localhost:5000"
echo "- Network: http://YOUR_IP:5000"
echo
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo

python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident="Helpdesk Application" wsgi:app 