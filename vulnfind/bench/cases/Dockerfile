# Labelled benchmark case.
FROM python:3.8
# expect-above: RUNTIME-EOL
ENV API_TOKEN=abc123secret
# expect-above: DOCKER-SECRET-ENV
RUN curl -fsSL https://get.example.com/setup | bash
# expect-above: SH-CURL-PIPE
COPY . /app
CMD ["python", "app.py"]
