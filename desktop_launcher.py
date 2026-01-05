import threading
import webview
import time
from app import app

def run_flask():
    app.run(debug=False, use_reloader=False)

if __name__ == '__main__':
    # Run Flask server in a background thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    print("✅ Flask server is starting...")

    time.sleep(3)  # Give Flask time to start

    print("✅ Launching EcoClean window...")
    webview.create_window("EcoClean - Desktop Version", "http://127.0.0.1:5000")
    webview.start()  # <== Add this line to display the window
