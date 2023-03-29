FROM python:latest

COPY . /app
WORKDIR /app
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

RUN apt update && apt install -y libgl1-mesa-glx nano vim

COPY config-docker.cfg.sample /app/config.cfg
RUN sed -i 's/session = Unknown/session = Audit/g' config.cfg
RUN /bin/bash -c "echo \"PS1='\[\033[1;31m\]\u@\h\[\033[00m\]:\[\033[1;34m\]\w\[\033[00m\]\$ '\" >> /root/.bashrc "
RUN /bin/bash -c "echo \"alias ls='ls --color'\" >> /root/.bashrc "
