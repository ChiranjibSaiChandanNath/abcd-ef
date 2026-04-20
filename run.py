import os
from backend.app import create_app

app = create_app()

if __name__ == '__main__':
    # 1. Get the port from Render's environment, default to 5000 for local testing
    port = int(os.environ.get("PORT", 5000))
    
    print("Starting Malware Analysis Sandbox...")
    print(f"Server is initializing on port {port}...")

    # 2. host='0.0.0.0' is required for Render
    # 3. debug=False is safer for a live website
    app.run(host='0.0.0.0', port=port, debug=False)
