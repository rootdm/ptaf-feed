FROM python:3.10.12-slim

WORKDIR /app

COPY ptaf-feed.py ./

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "ptaf-feed.py"]

