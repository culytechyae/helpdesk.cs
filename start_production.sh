#!/bin/bash
echo "Starting Helpdesk Application in Production Mode..."
echo
echo "Installing/Updating dependencies..."
pip install -r requirements.txt
echo
echo "Starting Gunicorn server..."
gunicorn -c gunicorn.conf.py wsgi:app 