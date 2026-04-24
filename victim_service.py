import http.server
import socketserver

class AnomalyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # This simulates a 'Normal' request vs an 'Anomaly' request
        if "stress" in self.path:
            # ANOMALY: High CPU usage inside an open connection
            print("🚨 Simulating Anomaly...")
            sum(i*i for i in range(5000000)) 
        else:
            # NORMAL: Low CPU usage
            print("✅ Normal Request")
            
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Done")

with socketserver.TCPServer(("", 8080), AnomalyHandler) as httpd:
    print("Victim service running on port 8080...")
    httpd.serve_forever()

