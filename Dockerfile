# AutoSupplyGuard Dockerfile
FROM python:3.10-slim

# Set working directory and environment variables
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY app/ app/
COPY dashboard/ dashboard/
COPY data/ data/
COPY docs/ docs/
COPY research/ research/
COPY scripts/ scripts/
COPY tests/ tests/
COPY README.md LICENSE ./

# Install dependencies
RUN pip install --no-cache-dir -e .

# Expose FastAPI and Streamlit ports
EXPOSE 8000 8501

# Default command launches FastAPI backend
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
