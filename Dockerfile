FROM python:3.13-slim

WORKDIR /app

# System deps (gcc for scipy/numpy wheels, libgomp for sklearn, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libgomp1 curl && rm -rf /var/lib/apt/lists/*

# Python deps (cached layer — only rebuilds when requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Source code
COPY . .

# Ensure state directory exists
RUN mkdir -p state models

# Default — run full 11-layer pipeline
CMD ["python", "run_demo.py", "--no-plots"]
