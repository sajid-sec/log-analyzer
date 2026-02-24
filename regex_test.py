import re

# A sample line matching your exact log format
log_line = '10.0.0.5 - [21/Feb/2026:11:23:00 +0530] "POST /login.php HTTP/1.1" 401'

# Compile the master regex with named capture groups
# It looks for: Start of line IP -> dash -> [Timestamp] -> "Request" -> Status Code
LOG_PATTERN = re.compile(r'^(?P<ip>[\d\.]+)\s+-\s+\[(?P<timestamp>[^\]]+)\].*?"\s+(?P<status>\d{3})')

# Search the line
match = LOG_PATTERN.search(log_line)

# If it perfectly matches our expected log format, extract the named variables
if match:
    print(f"Extracted IP: {match.group('ip')}")
    print(f"Extracted Time: {match.group('timestamp')}")
    print(f"Extracted Status: {match.group('status')}")
else:
    print("Regex failed to match the log format.")
