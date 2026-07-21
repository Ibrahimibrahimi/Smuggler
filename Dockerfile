FROM python:3.12-slim

LABEL maintainer="idwahman" \
      description="HTTP Request Smuggling Vulnerability Scanner"

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["smuggler"]
CMD ["--help"]
