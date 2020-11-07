import configparser
import sys
import os.path

class Config:

    @classmethod
    def load_config(self):
        self.config = configparser.ConfigParser()

        if os.path.isfile(os.path.join(os.path.dirname(sys.argv[0]), 'config.cfg')):
            self.config.read(os.path.join(os.path.dirname(sys.argv[0]), 'config.cfg'))
        else:
            print('Please create the config.cfg file from config.cfg.sample')
            sys.exit()

        session = self.config.get('Global', 'session')
        if session == None or session == 'Unknown':
            print('Please set a session name')
            sys.exit()

