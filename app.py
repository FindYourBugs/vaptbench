"""Run: python app.py  (http://127.0.0.1:8090)"""
import urllib3
from vaptbench import create_app

urllib3.disable_warnings()  # target TLS is often self-signed in test
app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8090, debug=True)
