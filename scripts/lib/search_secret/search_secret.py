import os
import re
import magic
import configparser

from utils.output import Output
from utils.db import DB

# parsed using the textract library - taken from MANSPIDER
textract_extensions = [
    'doc',
    'docx',
    'xls',
    'xlsx',
    'ppt',
    'pptx',
    'pdf',
    'eml',
    'png',
    'jpg',
    'jpeg'
]


def decode_bytes(data, file_type):
    """Decode bytes from all encodings"""

    if 'UTF-8 (with BOM)' in file_type:
        return data.decode('utf-8-sig', errors='replace')
    elif 'UTF-16 (with BOM)' in file_type:
        return data.decode('utf-16', errors='replace')
    elif 'UTF-16, little-endian' in file_type:
        return data.decode('utf-16', errors='replace')
    elif 'UTF-16, big-endian' in file_type:
        return data.decode('utf-16', errors='replace')
    elif 'ASCII text' in file_type:
        return data.decode(errors='replace')
    return data.decode(errors='replace')

class SearchSecret:
    
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(__file__), "..", "..", "..", "secret_search.conf")
        self.config  = configparser.ConfigParser()
        self.config.read(self.config_file)

    def to_check(self, filename, file_size):
        
        ignored_extensions  = self.config['General']['ignored_extensions'].split(',')

        if any([filename.endswith(".%s" % ext) for ext in ignored_extensions]):
            return False

        if file_size > int(self.config['General']['max_file_size']):
            return False

        return True

    def search_secret(self, filename, filepath, data):
        if any([filename.endswith(".%s" % ext) for ext in textract_extensions]):
            # Not supported yet
            return
            
        mime = magic.from_buffer(data, mime=True)
        file_type = magic.from_buffer(data)

        if '://' in filepath:
            service = filepath.split('://')[0]
        else:
            service = None

        if mime.endswith('charset-binary') or file_type.endswith('data'):
            if mime.startswith('application/pdf'):
                # Not supported yet
                return
               
                """
                import pdftotext
                with io.BytesIO(data) as fp:
                    pdf = pdftotext.PDF(fp)
                return '\n\n'.join(pdf)
                """
            elif "text" in file_type:
                data_str = decode_bytes(data, file_type)
            else:
                return
        else:
            data_str = decode_bytes(data, file_type)

        for line in data_str.split('\n'):
            line = line.strip()

            for secret_pattern_name in self.config['General']['secret_patterns'].split(','):
                pattern = self.config[secret_pattern_name]['regex']

                # TODO
                if re.compile(pattern).search(line):
                    false_positive_string = self.config[secret_pattern_name]['false_positive_string']
                    if len(false_positive_string) > 0:
                        fp_strings = false_positive_string.split(',')
                    else:
                        fp_strings = []
                    
                    if any([fp in line for fp in fp_strings]):
                        # False positive, ignore
                        continue

                    reliability = self.config[secret_pattern_name]['reliability']

                    secret = {
                        'filepath': filepath,
                        'secret_name': secret_pattern_name,
                        'line': line,
                        'reliability': reliability,
                        'service': service,
                    }

                    Output.vuln({'target': secret['filepath'], 'message': '%s SECRET: %s' % (("[%s]" % secret['secret_name']).ljust(20), secret['line'])})
                    DB.insert_secret(secret)




