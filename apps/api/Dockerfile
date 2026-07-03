FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml ./
COPY uv.lock* ./
RUN uv sync --no-dev || uv sync

COPY . .

EXPOSE 8000
CMD ["uv", "run", "uvicorn", "prahari.main:app", "--host", "0.0.0.0", "--port", "8000"]
