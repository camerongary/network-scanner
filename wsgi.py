#!/usr/bin/env python3
"""
WSGI entry point for Gunicorn.
Initializes the Flask app and starts the background scanner.
"""

from app import app, startup_scanner
import sys

# Initialize the scanner on startup
try:
    startup_scanner()
except Exception as e:
    print(f"Error initializing scanner: {str(e)}", file=sys.stderr)

# Export the app for Gunicorn
if __name__ == '__main__':
    app.run()
