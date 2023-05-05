def parse_unix_passwd(passwd_content):
    hashes = []

    for line in passwd_content.split("\n"):
        line = line.strip()

        items = line.split(":")

        if len(items) < 5: # should be equal 9 but just in case...
            continue

        username = items[0]
        hash = items[1]

        if hash in ["x", "*", "!!", "!"] or hash.startswith("!"):
            continue

        hashes.append({
            "username": username,
            "hash": hash,
            "format": "unknown",
        })

    return hashes

def parse_unix_shadow(shadow_content):
    hashes = []

    for line in shadow_content.split("\n"):
        line = line.strip()

        items = line.split(":")

        if len(items) < 5: # should be equal 9 but just in case...
            continue

        username = items[0]
        hash = items[1]

        if hash in ["x", "*", "!!", "!"] or hash.startswith("!"):
            continue

        if hash.startswith("$1$"):
            format = "md5"
        elif hash.startswith("$2"):
            format = "blowfish"
        elif hash.startswith("$5$"):
            format = "sha256"
        elif hash.startswith("$6$"):
            format = "sha512"
        else:
            format = "unknown"

        hashes.append({
            "username": username,
            "hash": hash,
            "format": format,
        })

    return hashes
