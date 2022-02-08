#!/usr/bin/python3
import time
from rsh_listener.listener import Listener
from rsh_listener.prompt import Prompt

def main():
    # Grab the config
    bind_ip = '0.0.0.0'
    bind_port = 4444

    try:
        # start the listener
        listener = Listener(bind_ip, bind_port)
        listener.start()

        time.sleep(1)

        prompt = Prompt(listener)
        prompt.start()

    except Exception as e:
        print('%s: %s' % (type(e), e))

if __name__ == '__main__':
    main()

