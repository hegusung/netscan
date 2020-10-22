import os.path
import copy

def dir_file_count(dir_file):
    count = 0

    f = open(dir_file)
    for dir_item in f:
        dir_item = dir_item.split('#')[0].strip()
        if len(dir_item) == 0:
            continue

        count += 1

    f.close()

    return count

def dir_bruteforce_generator(target, dir_file, extension_list):
    f = open(dir_file)
    for dir_item in f:
        dir_item = dir_item.split('#')[0].strip()
        if len(dir_item) == 0:
            continue

        for extension in extension_list:
            if len(extension) != 0:
                path = os.path.join(target['path'], "%s.%s" % (dir_item, extension))
            else:
                path = os.path.join(target['path'], dir_item)

            t = copy.copy(target)
            t['path'] = path

            yield t

    f.close()

