class BSON:

    @classmethod
    def decode(self, bson_data):
        if bson_data[0] == 1:
            return None, 1

        elif bson_data[0] == 2:
            if bson_data[1] == 1:
                return True, 2
            else:
                return False, 2

        elif bson_data[0] == 3:
            return int.from_bytes(bson_data[1:5], "little"), 5

        elif bson_data[0] == 4:

            size = int.from_bytes(bson_data[1:5], "little")
            bson_str = bson_data[5:5+size].decode()

            i = 5 + size + 1
            
            return bson_str, i

        elif bson_data[0] == 5:
            array = []
            i = 1
            while bson_data[i] != 0:
                item, count = BSON.decode(bson_data[i:])
                array.append(item)
                i += count

            i += 1

            return array, i

        elif bson_data[0] == 6:
            d = {}
            i = 1

            while bson_data[i] != 0:
                key, j = BSON.decode_str(bson_data[i:])
                item, k = BSON.decode(bson_data[i+j:])

                d[key] = item
                i += j + k

            i += 1

            return d, i

        else:
            raise Exception("Bad BSON")


    @classmethod
    def encode(self, json_data):
        bson_data = b""
        if json_data == None:
            bson_data += bytes([1])
            return bson_data

        elif type(json_data) == bool:
            bson_data += bytes([2])
            if json_data:
                return bson_data + bytes([1])
            else:
                return bson_data + bytes([0])

        elif type(json_data) == int:
            bson_data += bytes([3])
            return bson_data + json_data.to_bytes(4, 'little')

        elif type(json_data) == str:
            bson_data += bytes([4])
            return bson_data + len(json_data).to_bytes(4, 'little') + json_data.encode() + bytes([0])

        elif type(json_data) == list:
            bson_data += bytes([5])
            for item in json_data:
                bson_data += BSON.encode(item)
            bson_data += bytes([0])

            return bson_data

        elif type(json_data) == dict:
            bson_data += bytes([6])
            for key, item in json_data.items():
                bson_data += key.encode() + bytes([0])
                bson_data += BSON.encode(item)
            bson_data += bytes([0])

            return bson_data

        else:
            raise Exception("BSON.encode: wrong type: %s" % type(json_data))

    @classmethod
    def decode_str(self, bson_data):
        bson_str = b""
        i = 0

        while bson_data[i] != 0:
            bson_str += bytes([bson_data[i]])
            i += 1
        
        i += 1
        return bson_str.decode(), i

