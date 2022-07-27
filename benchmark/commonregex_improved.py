from types import MethodType
import re

date = "(?i)(?:[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}"
time = '\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?'
phone = '''((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))'''
phones_with_exts = '((?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?))'
link = r'(?:(?:https?:\/\/)?(?:[a-z0-9.\-]+|www|[a-z0-9.\-])[.](?:[^\s()<>]+|\((?:[^\s()<>]+|(?:\([^\s()<>]+\)))*\))+(?:\((?:[^\s()<>]+|(?:\([^\s()<>]+\)))*\)|[^\s!()\[\]{};:\'".,<>?]))'
email = r"([a-z0-9!#$%&'*+\/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"
ipv4 = '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ipv6 = '\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*'
ip_pattern = ipv4 + '|' + ipv6
price = '[$]\s?[+-]?[0-9]{1,3}(?:(?:,?[0-9]{3}))*(?:\.[0-9]{1,2})?'
hex_color = '(#(?:[0-9a-fA-F]{8})|#(?:[0-9a-fA-F]{3}){1,2})\\b'
credit_card = '((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])'
btc_address = '(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])'
street_address = '\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?=\s|$)'
zip_code = r'\b\d{5}(?:[-\s]\d{4})?\b'
po_box = r'P\.? ?O\.? Box \d+'
ssn = '(?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[- ](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}'
git_repo = "((git|ssh|http(s)?)|(git@[\w\.]+))(:(\/\/)?)([\w\.@\:/\-~]+)(\.git)(\/)?"

regex_map = {
    "dates": date,
    "times": time,
    "phones": phone,
    "phones_with_exts": phones_with_exts,
    "emails": email,
    "links": link,
    "ipv4": ipv4,
    "ipv6": ipv6,
    "ips": ip_pattern,
    "prices": price,
    "hex_colors": hex_color,
    "credit_cards": credit_card,
    "btc_addresses": btc_address,
    "street_addresses": street_address,
    "zip_codes": zip_code,
    "po_boxes": po_box,
    "ssn_number": ssn,
    "git_repos": git_repo
}

def match(text: str, regex: str) -> list:
    parsed = []
    parsed.append(re.findall(regex, text))
    parsed = sum(parsed, [])
    return parsed

def Dates(text: str) -> list:
    return match(text, regex_map["dates"])

def Times(text: str) -> list:
    return match(text, regex_map["times"])

def Phones(text: str) -> list:
    return match(text, regex_map["phones"])

def Phones_with_exts(text: str) -> list:
    return match(text, regex_map["phones_with_exts"])

def Links(text: str) -> list:
    return match(text, regex_map["links"])

def IPV4s(text: str) -> list:
    return match(text, regex_map["ipv4"])

def IPV6s(text: str) -> list:
    return match(text, regex_map["ipv6"])

def IPs(text: str) -> list:
    return match(text, regex_map["ips"])

def Prices(text: str) -> list:
    return match(text, regex_map["prices"])

def Hex_Colors(text: str) -> list:
    return match(text, regex_map["hex_colors"])

def Credit_Cards(text: str) -> list:
    return match(text, regex_map["credit_cards"])

def Btc_Address(text: str) -> list:
    return match(text, regex_map["btc_addresses"])

def Street_Addresses(text: str) -> list:
    return match(text, regex_map["street_addresses"])

def Zip_Codes(text: str) -> list:
    return match(text, regex_map["zip_codes"])

def Po_Boxes(text: str) -> list:
    return match(text, regex_map["po_boxes"])

def Ssn(text: str) -> list:
    return match(text, regex_map["ssn_number"])

def Git_Repo(text: str) -> list:
    return match(text, regex_map["git_repos"])