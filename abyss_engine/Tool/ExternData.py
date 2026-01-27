import re
from datetime import datetime

# File path
file_path = "./Tool/ExternData.cs"

# Current time formatted as YYYY-MM-DD:HH:MM
current_time = datetime.now().strftime("%Y-%m-%d:%H:%M")

# Read file
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the BuildTime value
new_content = re.sub(
    r'(public const string BuildTime = )".*";',
    rf'\1"{current_time}";',
    content
)

# Write back
with open(file_path, "w", encoding="utf-8") as f:
    f.write(new_content)

print(f"Updated BuildTime to {current_time}")
