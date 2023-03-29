# Docker bashrc

prompt_color='\[\033[1;34m\]'
path_color='\[\033[1;32m\]'
if [ "$EUID" -eq 0 ]; then # Change prompt colors for root user
prompt_color='\[\033[1;31m\]'
path_color='\[\033[1;34m\]'
fi
PS1='${debian_chroot:+($debian_chroot)}'$prompt_color'\u@\h\[\033[00m\]:'$path_color'\w\[\033[00m\]\$ '
unset prompt_color path_color
