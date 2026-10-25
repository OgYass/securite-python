import re

def check_ioc(data):
    TEXT = re.findall(rb"[\x20-\x7e]{4,}", data)
    DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
    IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    URL = re.compile(r"https?://[^\s\"']+")

    return {"TEXT":TEXT,"DOMAIN":DOMAIN,"IPV4":IPV4,"URL":URL}