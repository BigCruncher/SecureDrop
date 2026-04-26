FROM python:3.11-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN pip install pycryptodome pyyaml
CMD ["sleep", "infinity"]
