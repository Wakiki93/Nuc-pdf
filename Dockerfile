FROM python:3.11-slim

LABEL maintainer="NucleiReport"
LABEL description="Professional PDF report generator for Nuclei scan results"

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY nucleireport/ nucleireport/
COPY pyproject.toml .

# Install the package
RUN pip install --no-cache-dir .

# Default working directory for input/output
WORKDIR /data

ENTRYPOINT ["nucleireport"]
CMD ["--help"]
