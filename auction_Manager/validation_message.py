import json
from jsonschema import validate

"""
Formato para pedido de timestamp por parte do cliente
dateTime = str(datetime.datetime.now())
"""

# Bid schema
bid_schema = {
  "type" : "object",
  "properties" : {
    "uuid" : {"type": "string"},
    "amount" : {"type": "number"},
    "auction_id" : {"type": "number"},
    "type" : {"type": "string"}
  },
}
# Auction schema
auction_schema = {
  "type" : "object",
  "properties" : {
    "uuid" : {"type": "string"},
    "name" : {"type": "string"},
    "serial_number" : {"type": "number"},
    "description" : {"type": "string"},
    "duration" : {"type": "number"},
    "amount" : {"type": "number"},
    "tipo" : {"type": "string"},
    "type" : {"type": "string"}
  }
}

# Bid schema
bid_schema2 = {
  "type" : "object",
  "properties" : {
    "uuid" : {"type": "string"},
    "amount" : {"type": "number"},
    "auction_id" : {"type": "number"},
    "cryptopuzzle" : {"type": "number"},
    "type" : {"type": "string"}
  },
}

class Validation:
  def validateSchema(json_reader,tipo):
    """
    Function that validates json objects.
    Intially verifies if the message is an json object, if it's a json object
    e validate the specific schema (bid, auction, message), otherwise message
    error is returned.
    -----
    Parameters
    json_object - The json object.
    -----
    Returns
    valid_schema if schema is valid and exists a schema model for it.
    wrong_schema if schema isn't valid and exists a schema model for it.
    not_a_schema if schema model doesn't exists for it.
    """

    valid_schema = "Schema is valid"
    wrong_schema = "Schema not valid"
    not_a_schema = "Not a valid schema type"

    #bid
    if (tipo == "bid"):
      try:
        validate(json_reader, bid_schema)
        print(valid_schema)
        return True
      except:
        print(wrong_schema)
        return False

    #auction
    elif (tipo == "auction"):
      try:
        validate(json_reader, auction_schema)
        return True
      except:
        return False

    #bid2
    elif (tipo == "bid2"):
      try:
        validate(json_reader, bid_schema2)
        return True
      except:
        return False

    else:
      return False