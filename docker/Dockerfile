FROM python:latest

WORKDIR /app

# System requirements
RUN apt update && apt install -y libgl1-mesa-glx nano vim iputils-ping nmap ntpdate
RUN wget https://github.com/lsd-rs/lsd/releases/download/0.23.1/lsd_0.23.1_amd64.deb -O /tmp/lsd.deb
RUN dpkg -i /tmp/lsd.deb >/dev/null 2>&1 && rm -f /tmp/lsd.deb

# Python requirements
RUN pip install --upgrade pip
COPY ./requirements.txt  /app/requirements.txt
RUN pip install -r /app/requirements.txt

# App requirements
COPY . /app

# Make things useful 
RUN echo 'root:netscan' | chpasswd
RUN useradd -ms /bin/bash user

# Make things beautiful 🥰
RUN /bin/bash -c "echo \"PS1='\[\033[1;31m\]\u@\h\[\033[00m\]:\[\033[1;34m\]\w\[\033[00m\]\$ '\" >> /root/.bashrc "
RUN /bin/bash -c "echo \"alias ls='lsd'\" >> /root/.bashrc"
RUN /bin/bash -c "echo \"alias ll='ls -al'\" >> /root/.bashrc"
RUN /bin/bash -c "echo \"PS1='\[\033[1;31m\]\u@\h\[\033[00m\]:\[\033[1;34m\]\w\[\033[00m\]\$ '\" >> /home/user/.bashrc "
RUN /bin/bash -c "echo \"alias ls='lsd'\" >> /home/user/.bashrc"
RUN /bin/bash -c "echo \"alias ll='ls -al'\" >> /home/user/.bashrc"

USER user 
ENTRYPOINT [ "./netscan" ]