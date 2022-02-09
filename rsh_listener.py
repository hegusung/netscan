#!/usr/bin/python3
import time
import traceback
from server.rsh_listener.listener import Listener
from server.rsh_listener.prompt import Prompt

from utils.config import Config
from utils.output import Output

def main():
    # Setup output
    Output.setup()

    # Grab the config
    Config.load_config()
    bind_ip = Config.config.get('ReverseshellListener', 'bind_ip')
    bind_port = int(Config.config.get('ReverseshellListener', 'bind_port'))

    try:
        # start the listener
        listener = Listener(bind_ip, bind_port)
        listener.start()

        time.sleep(1)

        prompt = Prompt(listener)
        prompt.start()
    except KeyboardInterrupt:
        Output.stop()
        pass
    except Exception as e:
        Output.stop()
        print('%s: %s\n%s' % (type(e), e, traceback.format_exc()))

if __name__ == '__main__':
    main()

