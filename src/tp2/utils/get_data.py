import hashlib
import magic
from tp2.utils.config import logger
import math
from collections import Counter



def get_data(path:str) -> dict :
    """
    Recupere et renvoi les datas d'un fichier
    """
    data = get_file(path)
    metadata = get_metadata(data)
    return metadata

def get_file(path) :
    data = open(path, 'rb').read()
    return data

def get_metadata(data) -> dict:
    """
        recupere les metadata d'un set de datas
    """
    sha256  = hashlib.sha256(data).hexdigest()
    md5     = hashlib.md5(data).hexdigest()
    ftype   = magic.from_buffer(data)
    size    = len(data)
    entropy = entropy_calc(data)

    return {"sha256": sha256, "md5": md5, "ftype": ftype, "size": size, "entropy": entropy }

def entropy_calc(data:bytes) -> float:
    """
        calcul de l'entropy d'un set de data
    """
    if not data:
        return 0.0

    freq = Counter(data)
    entropy = -sum((c / len(data)) * math.log2(c /len(data)) for c in freq.values())
    return entropy