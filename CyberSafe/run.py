"""
CyberSafe - Run script

Simple entry point to start the CyberSafe web application.

Usage:
    python run.py              # Start development server
    flask run                  # Also works if FLASK_APP is set
"""

import sys
import os
import subprocess

def main():
    """Start the CyberSafe Flask application."""
    # Add the app directory to Python path if needed
    app_dir = os.path.dirname(os.path.abspath(__file__))
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    venv_python = os.path.join(app_dir, ".venv", "Scripts", "python.exe")
    if os.name == "nt" and os.path.isfile(venv_python) and sys.prefix == sys.base_prefix:
        try:
            return_code = subprocess.call(
                [venv_python, os.path.abspath(__file__), *sys.argv[1:]]
            )
        except KeyboardInterrupt:
            raise SystemExit(130)
        raise SystemExit(return_code)

    from app import create_app

    app = create_app()

    # Development server configuration
    debug = os.environ.get("FLASK_DEBUG", "").lower() == "true"
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))

    print("=" * 50)
    print("CyberSafe - Cybersecurity Learning Platform")
    print("=" * 50)
    print(f"Server running at: http://{host}:{port}/")
    print(f"Debug mode: {debug}")
    print()
    print("Features available:")
    print("  • Student registration and login")
    print("  • Quiz modules with 5 questions each")
    print("  • Admin panel with quiz results tracking")
    print("  • Progress dashboard for students")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 50)

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()