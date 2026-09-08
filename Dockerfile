# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim-bookworm AS runtime
RUN pip install --no-cache-dir uv==0.8.22
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1
WORKDIR /app
COPY pyproject.toml uv.lock LICENSE LICENSE-APACHE-2.0 ./
COPY LICENSES ./LICENSES
RUN uv sync --frozen --no-dev --no-install-project
COPY distributedai ./distributedai
RUN uv sync --frozen --no-dev && useradd --uid 10001 --create-home app
ENV PATH="/app/.venv/bin:$PATH" BIND_HOST=0.0.0.0
USER 10001
EXPOSE 8090
CMD ["distributedai", "serve"]

# Select only when cloud-managed keys are needed; the default image stays small.
FROM runtime AS cloud-keys
USER root
RUN uv sync --frozen --no-dev --all-extras
USER 10001

FROM runtime AS test
USER root
RUN uv sync --frozen
COPY tests ./tests
COPY scripts ./scripts
USER 10001
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]

# A plain docker build produces the service, not the test runner.
FROM runtime AS production
