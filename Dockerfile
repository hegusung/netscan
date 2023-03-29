FROM python:latest

COPY . /app
WORKDIR /app
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

RUN apt update && apt install nano

COPY config-docker.cfg.sample /app/config.cfg
RUN sed -i 's/session = Unknown/session = Audit/g' config.cfg