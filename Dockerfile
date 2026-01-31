# Kiro Gateway - Docker Image
# Optimized single-stage build with uv

FROM python:3.14-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1

# Create non-root user for security
RUN groupadd -r kiro && useradd -r -g kiro kiro

# Set working directory
WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files first (better layer caching)
COPY pyproject.toml uv.lock ./

RUN uv pip install --system -r pyproject.toml

# Copy application code
COPY --chown=kiro:kiro . .

# Create directory for debug logs with proper permissions
RUN mkdir -p debug_logs && chown -R kiro:kiro debug_logs

# Switch to non-root user
USER kiro

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=5)"

# Run the application
CMD ["python", "main.py"]
