
# import http.server
# import socketserver
# from urllib import request, error
# import logging
# import hashlib
# import os
# import threading
# import time
# from datetime import datetime

# # Caching Directory
# CACHE_DIR = "proxy_cache"
# if not os.path.exists(CACHE_DIR):
#     os.makedirs(CACHE_DIR)

# # Blocked URLs/IPs List
# BLOCKED = ["example.com", "blockedsite.com"]
# ALLOWED = []
# LOGS = []
# LOG_PATH = "proxy_logs.txt"

# # Custom Headers
# CUSTOM_HEADERS = {"User-Agent": "MyCustomProxy/1.0"}

# # Rate Limiting
# REQUESTS_PER_MINUTE = 60
# RATE_LIMIT = {}

# # Authentication
# AUTHORIZED_USERS = {"admin": "password"}  # username:password

# # Proxy Handler
# class ProxyHandler(http.server.SimpleHTTPRequestHandler):
#     def do_GET(self):
#         url = self.path[1:]  # Remove leading '/'
#         client_ip = self.client_address[0]
#         current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
#         # Rate Limiting
#         if client_ip in RATE_LIMIT:
#             last_request_time = RATE_LIMIT[client_ip]
#             time_diff = (datetime.now() - last_request_time).seconds
#             if time_diff < 60 / REQUESTS_PER_MINUTE:
#                 self.send_response(429)  # Too Many Requests
#                 self.end_headers()
#                 self.wfile.write(b"Rate limit exceeded. Try again later.")
#                 return
#         RATE_LIMIT[client_ip] = datetime.now()

#         # Authentication
#         if not self.headers.get('Authorization') == "Basic YWRtaW46cGFzc3dvcmQ=":  # base64 "admin:password"
#             self.send_response(401)  # Unauthorized
#             self.send_header("WWW-Authenticate", 'Basic realm="Proxy Server"')
#             self.end_headers()
#             self.wfile.write(b"Unauthorized Access")
#             return

#         # Blocked URLs
#         if any(blocked in url for blocked in BLOCKED):
#             self.send_response(403)
#             self.end_headers()
#             self.wfile.write(b"Access Denied: Blocked URL")
#             self.log_request(current_time, url, "Blocked URL")
#             return

#         # Cache Check
#         cache_key = hashlib.md5(url.encode()).hexdigest()
#         cache_file = os.path.join(CACHE_DIR, cache_key)

#         if os.path.exists(cache_file):
#             with open(cache_file, "rb") as f:
#                 logging.info(f"Serving from cache: {url}")
#                 self.send_response(200)
#                 self.end_headers()
#                 self.wfile.write(f.read())
#                 self.log_request(current_time, url, "Cache hit")
#                 return

#         try:
#             req = request.Request(url, headers=CUSTOM_HEADERS)
#             with request.urlopen(req) as response:
#                 content = response.read()

#                 # Cache the response
#                 with open(cache_file, "wb") as f:
#                     f.write(content)

#                 self.send_response(200)
#                 self.send_header("Content-Type", response.headers["Content-Type"])
#                 self.end_headers()
#                 self.wfile.write(content)
#                 self.log_request(current_time, url, "Served from source")
#         except error.URLError as e:
#             logging.error(f"Error fetching {url}: {e}")
#             self.send_response(500)
#             self.end_headers()
#             self.wfile.write(b"Internal Proxy Error")
#             self.log_request(current_time, url, "Error")

#     def log_request(self, timestamp, url, status):
#         log_entry = f"{timestamp} - {status}: {url}"
#         LOGS.append(log_entry)
#         with open(LOG_PATH, "a") as f:
#             f.write(log_entry + "\n")

#     def log_message(self, format, *args):
#         logging.info(f"{self.client_address[0]} - {format % args}")

# class ProxyServer(threading.Thread):
#     def __init__(self, port=8080):
#         super().__init__()
#         self.port = port
#         self.httpd = None

#     def run(self):
#         with socketserver.TCPServer(("", self.port), ProxyHandler) as httpd:
#             self.httpd = httpd
#             logging.info(f"Proxy server running on port {self.port}")
#             httpd.serve_forever()

#     def stop(self):
#         if self.httpd:
#             self.httpd.shutdown()
#             logging.info("Proxy server stopped")







