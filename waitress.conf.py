# Waitress configuration file for production
import os

# Server configuration
host = "0.0.0.0"
port = 5000
threads = 4
connection_limit = 1000
cleanup_interval = 30
ident = "Helpdesk Application"
max_request_body_size = 1073741824  # 1GB
buffer_size = 16384
asyncore_use_poll = True
log_socket_errors = True
unix_socket = None
unix_socket_perms = "600"
url_scheme = "http"
url_prefix = ""
clear_untrusted_proxy_headers = True
log_untrusted_proxy_headers = False
trusted_proxy = None
trusted_proxy_headers = None
trusted_proxy_count = None
remove_hop_by_hop_headers = True 