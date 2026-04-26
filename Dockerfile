FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install pycryptodome pyyaml
CMD ["python", "tcp_client.py"]