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
    
    def __init__(self, keyword=None):
        self.keyword = keyword

        self.config_file = os.path.join(os.path.dirname(__file__), "..", "..", "..", "secret_search.conf")
        self.config  = configparser.ConfigParser()
        self.config.read(self.config_file)

        self.previous_lines = int(self.config['General']['previous_lines'])
        self.after_lines = int(self.config['General']['after_lines'])

    def to_check(self, filename, file_size):
        
        ignored_extensions  = self.config['General']['ignored_extensions'].split(',')

        if any([filename.endswith(".%s" % ext) for ext in ignored_extensions]):
            return False

        if file_size > int(self.config['General']['max_file_size']):
            return False

        return True

    def search_secret(self, filename, filepath, data, file_info):
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

        lines = data_str.split('\n')
        for line_index in range(len(lines)):
            line = lines[line_index].strip()

            if self.keyword == None or self.keyword == '':
                for secret_pattern_name in self.config['General']['secret_patterns'].split(','):
                    pattern = self.config[secret_pattern_name]['regex']

                    if re.compile(pattern, re.IGNORECASE).search(line):
                        false_positive_string = self.config[secret_pattern_name]['false_positive_string']
                        if len(false_positive_string) > 0:
                            fp_strings = false_positive_string.split(',')
                        else:
                            fp_strings = []
                        
                        if any([fp in line for fp in fp_strings]):
                            # False positive, ignore
                            continue

                        reliability = self.config[secret_pattern_name]['reliability']

                        block = self.get_previous_after(lines, line_index)

                        secret = {
                            'filepath': filepath,
                            'secret_name': secret_pattern_name,
                            'line': block,
                            'reliability': reliability,
                            'service': service,
                        }

                        if 'creation_time' in file_info:
                            secret['created_date'] = file_info['creation_time']
                        if 'last_access' in file_info:
                            secret['last_access'] = file_info['last_access']
                        if 'last_modification' in file_info:
                            secret['last_modification'] = file_info['last_modification']

                        Output.vuln({'target': secret['filepath'], 'message': '%s SECRET: %s' % (("[%s]" % secret['secret_name']).ljust(20), line)})
                        DB.insert_secret(secret)
            else:
                pattern = self.keyword

                if re.compile(pattern, re.IGNORECASE).search(line):
                    reliability = 'N/A'

                    block = self.get_previous_after(lines, line_index)

                    secret = {
                        'filepath': filepath,
                        'secret_name': "keyword:%s" % self.keyword,
                        'line': block,
                        'reliability': reliability,
                        'service': service,
                    }

                    if 'creation_time' in file_info:
                        secret['created_date'] = file_info['creation_time']
                    if 'last_access' in file_info:
                        secret['last_access'] = file_info['last_access']
                    if 'last_modification' in file_info:
                        secret['last_modification'] = file_info['last_modification']

                    Output.vuln({'target': secret['filepath'], 'message': '%s SECRET: %s' % (("[keyword:%s]" % self.keyword).ljust(20), line)})
                    DB.insert_secret(secret)



    def get_previous_after(self, lines, line_index):
        start = line_index - self.previous_lines
        if start < 0:
            start = 0
        end = line_index + self.after_lines
        if end >= len(lines):
            end = len(lines) - 1

        return "\n".join(lines[start:end + 1])
