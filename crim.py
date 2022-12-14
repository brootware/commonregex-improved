import re

date = "(?i)(?:[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}"
time = '(?i)\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?'
phone = '''((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))'''
phones_with_exts = '(?i)(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?)'
link = r'(?i)((?:https?://|www\d{0,3}[.])?[a-z0-9.\-]+[.](?:(?:international)|(?:construction)|(?:contractors)|(?:enterprises)|(?:photography)|(?:immobilien)|(?:management)|(?:technology)|(?:directory)|(?:education)|(?:equipment)|(?:institute)|(?:marketing)|(?:solutions)|(?:builders)|(?:clothing)|(?:computer)|(?:democrat)|(?:diamonds)|(?:graphics)|(?:holdings)|(?:lighting)|(?:plumbing)|(?:training)|(?:ventures)|(?:academy)|(?:careers)|(?:company)|(?:domains)|(?:florist)|(?:gallery)|(?:guitars)|(?:holiday)|(?:kitchen)|(?:recipes)|(?:shiksha)|(?:singles)|(?:support)|(?:systems)|(?:agency)|(?:berlin)|(?:camera)|(?:center)|(?:coffee)|(?:estate)|(?:kaufen)|(?:luxury)|(?:monash)|(?:museum)|(?:photos)|(?:repair)|(?:social)|(?:tattoo)|(?:travel)|(?:viajes)|(?:voyage)|(?:build)|(?:cheap)|(?:codes)|(?:dance)|(?:email)|(?:glass)|(?:house)|(?:ninja)|(?:photo)|(?:shoes)|(?:solar)|(?:today)|(?:aero)|(?:arpa)|(?:asia)|(?:bike)|(?:buzz)|(?:camp)|(?:club)|(?:coop)|(?:farm)|(?:gift)|(?:guru)|(?:info)|(?:jobs)|(?:kiwi)|(?:land)|(?:limo)|(?:link)|(?:menu)|(?:mobi)|(?:moda)|(?:name)|(?:pics)|(?:pink)|(?:post)|(?:rich)|(?:ruhr)|(?:sexy)|(?:tips)|(?:wang)|(?:wien)|(?:zone)|(?:biz)|(?:cab)|(?:cat)|(?:ceo)|(?:com)|(?:edu)|(?:gov)|(?:int)|(?:mil)|(?:net)|(?:onl)|(?:org)|(?:pro)|(?:red)|(?:tel)|(?:uno)|(?:xxx)|(?:ac)|(?:ad)|(?:ae)|(?:af)|(?:ag)|(?:ai)|(?:al)|(?:am)|(?:an)|(?:ao)|(?:aq)|(?:ar)|(?:as)|(?:at)|(?:au)|(?:aw)|(?:ax)|(?:az)|(?:ba)|(?:bb)|(?:bd)|(?:be)|(?:bf)|(?:bg)|(?:bh)|(?:bi)|(?:bj)|(?:bm)|(?:bn)|(?:bo)|(?:br)|(?:bs)|(?:bt)|(?:bv)|(?:bw)|(?:by)|(?:bz)|(?:ca)|(?:cc)|(?:cd)|(?:cf)|(?:cg)|(?:ch)|(?:ci)|(?:ck)|(?:cl)|(?:cm)|(?:cn)|(?:co)|(?:cr)|(?:cu)|(?:cv)|(?:cw)|(?:cx)|(?:cy)|(?:cz)|(?:de)|(?:dj)|(?:dk)|(?:dm)|(?:do)|(?:dz)|(?:ec)|(?:ee)|(?:eg)|(?:er)|(?:es)|(?:et)|(?:eu)|(?:fi)|(?:fj)|(?:fk)|(?:fm)|(?:fo)|(?:fr)|(?:ga)|(?:gb)|(?:gd)|(?:ge)|(?:gf)|(?:gg)|(?:gh)|(?:gi)|(?:gl)|(?:gm)|(?:gn)|(?:gp)|(?:gq)|(?:gr)|(?:gs)|(?:gt)|(?:gu)|(?:gw)|(?:gy)|(?:hk)|(?:hm)|(?:hn)|(?:hr)|(?:ht)|(?:hu)|(?:id)|(?:ie)|(?:il)|(?:im)|(?:in)|(?:io)|(?:iq)|(?:ir)|(?:is)|(?:it)|(?:je)|(?:jm)|(?:jo)|(?:jp)|(?:ke)|(?:kg)|(?:kh)|(?:ki)|(?:km)|(?:kn)|(?:kp)|(?:kr)|(?:kw)|(?:ky)|(?:kz)|(?:la)|(?:lb)|(?:lc)|(?:li)|(?:lk)|(?:lr)|(?:ls)|(?:lt)|(?:lu)|(?:lv)|(?:ly)|(?:ma)|(?:mc)|(?:md)|(?:me)|(?:mg)|(?:mh)|(?:mk)|(?:ml)|(?:mm)|(?:mn)|(?:mo)|(?:mp)|(?:mq)|(?:mr)|(?:ms)|(?:mt)|(?:mu)|(?:mv)|(?:mw)|(?:mx)|(?:my)|(?:mz)|(?:na)|(?:nc)|(?:ne)|(?:nf)|(?:ng)|(?:ni)|(?:nl)|(?:no)|(?:np)|(?:nr)|(?:nu)|(?:nz)|(?:om)|(?:pa)|(?:pe)|(?:pf)|(?:pg)|(?:ph)|(?:pk)|(?:pl)|(?:pm)|(?:pn)|(?:pr)|(?:ps)|(?:pt)|(?:pw)|(?:py)|(?:qa)|(?:re)|(?:ro)|(?:rs)|(?:ru)|(?:rw)|(?:sa)|(?:sb)|(?:sc)|(?:sd)|(?:se)|(?:sg)|(?:sh)|(?:si)|(?:sj)|(?:sk)|(?:sl)|(?:sm)|(?:sn)|(?:so)|(?:sr)|(?:st)|(?:su)|(?:sv)|(?:sx)|(?:sy)|(?:sz)|(?:tc)|(?:td)|(?:tf)|(?:tg)|(?:th)|(?:tj)|(?:tk)|(?:tl)|(?:tm)|(?:tn)|(?:to)|(?:tp)|(?:tr)|(?:tt)|(?:tv)|(?:tw)|(?:tz)|(?:ua)|(?:ug)|(?:uk)|(?:us)|(?:uy)|(?:uz)|(?:va)|(?:vc)|(?:ve)|(?:vg)|(?:vi)|(?:vn)|(?:vu)|(?:wf)|(?:ws)|(?:ye)|(?:yt)|(?:za)|(?:zm)|(?:zw))(?:/[^\s()<>]+[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019])?)'
email = r"(?i)([A-Za-z0-9!#$%&'*+\/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"
ipv4 = '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ipv6 = '\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*'
ip_pattern = ipv4 + '|' + ipv6
not_known_ports   = '6[0-5]{2}[0-3][0-5]|[1-5][\d]{4}|[2-9][\d]{3}|1[1-9][\d]{2}|10[3-9][\d]|102[4-9]'
price = '[$]\s?[+-]?[0-9]{1,3}(?:(?:,?[0-9]{3}))*(?:\.[0-9]{1,2})?'
hex_color = '(#(?:[0-9a-fA-F]{8})|#(?:[0-9a-fA-F]{3}){1,2})\\b'
credit_card = '((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])'
visa_card = r"4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
master_card = r"5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
btc_address = '(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])'
street_address = '\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?=\s|$)'
zip_code = r'\b\d{5}(?:[-\s]\d{4})?\b'
po_box = r'(?i)P\.? ?O\.? Box \d+'
ssn = '(?:\d{3}-\d{2}-\d{4})'
md5_hashes = '[0-9a-fA-F]{32}'
sha1_hashes = '[0-9a-fA-F]{40}'
sha256_hashes = '[0-9a-fA-F]{64}'
isbn13 = '(?:[\d]-?){12}[\dxX]'
isbn10 = '(?:[\d]-?){9}[\dxX]'
mac_address = '(([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))'
iban_number = '[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z\d]?){0,16}'
git_repo = """((git|ssh|http(s)?)|(git@[\w\.]+))(:(\/\/)?)([\w\.@\:/\-~]+)(\.git)(\/)?"""


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
    "not_known_ports": not_known_ports,
    "prices": price,
    "hex_colors": hex_color,
    "credit_cards": credit_card,
    "visa_cards": visa_card,
    "master_cards": master_card,
    "btc_addresses": btc_address,
    "street_addresses": street_address,
    "zip_codes": zip_code,
    "po_boxes": po_box,
    "ssn_number": ssn,
    "md5_hashes": md5_hashes,
    "sha1_hashes": sha1_hashes,
    "sha256_hashes": sha256_hashes,
    "isbn13": isbn13,
    "isbn10": isbn10,
    "mac_addresses": mac_address,
    "iban_numbers": iban_number,
    "git_repos": git_repo
}

    
def match(text: str, regex: str) -> list:
    """Function to match using regex findall function
    Args:
        textchunk (str) : textchunk to be supplied to identify pattern
        regex (str) : regex to be used to match
    Returns:
        list (list): list of sensitive data found in lines
    """
    parsed = []
    parsed.append(re.findall(regex, text))
    parsed = sum(parsed, [])
    return parsed

def match_by_regex_search(text: str, regex: str) -> list:
    """Function to match using regex search function
    Args:
        textchunk (str) : textchunk to be supplied to identify pattern
        regex (str) : regex to be used to match
    Returns:
        list (list): list of sensitive data found in lines
    """
    parsed=[]
    for line in text.split():
        if re.search(regex, line):
            pattern_string = re.search(regex, line)
            sensitive_string = pattern_string.group(0)
            parsed.append(sensitive_string)
    return parsed

def dates(text: str) -> list:
    return match(text, regex_map["dates"])

def times(text: str) -> list:
    return match(text, regex_map["times"])

def phones(text: str) -> list:
    return match(text, regex_map["phones"])

def phones_with_exts(text: str) -> list:
    return match(text, regex_map["phones_with_exts"])

def emails(text:str) -> list:
    return match(text, regex_map["emails"])

def links(text: str) -> list:
    return match_by_regex_search(text, regex_map["links"])

def ipv4s(text: str) -> list:
    return match(text, regex_map["ipv4"])

def ipv6s(text: str) -> list:
    return match(text, regex_map["ipv6"])

def ips(text: str) -> list:
    return match(text, regex_map["ips"])

def not_known_ports(text: str) -> list:
    return match(text, regex_map["not_known_ports"])

def prices(text: str) -> list:
    return match(text, regex_map["prices"])

def hex_colors(text: str) -> list:
    return match(text, regex_map["hex_colors"])

def credit_cards(text: str) -> list:
    return match(text, regex_map["credit_cards"])

def visa_cards(text: str) -> list:
    return match(text, regex_map["visa_cards"])

def master_cards(text: str) -> list:
    return match(text, regex_map["master_cards"])

def btc_address(text: str) -> list:
    return match(text, regex_map["btc_addresses"])

def street_addresses(text: str) -> list:
    return match(text, regex_map["street_addresses"])

def zip_codes(text: str) -> list:
    return match(text, regex_map["zip_codes"])

def po_boxes(text: str) -> list:
    return match(text, regex_map["po_boxes"])

def ssn_numbers(text: str) -> list:
    return match(text, regex_map["ssn_number"])

def md5_hashes(text: str) -> list:
    return match(text, regex_map["md5_hashes"])

def sha1_hashes(text: str) -> list:
    return match(text, regex_map["sha1_hashes"])

def sha256_hashes(text: str) -> list:
    return match(text, regex_map["sha256_hashes"])

def isbn13s(text: str) -> list:
    return match(text, regex_map["isbn13"])

def isbn10s(text: str) -> list:
    return match(text, regex_map["isbn10"])

def mac_addresses(text: str) -> list:
    return match_by_regex_search(text, regex_map["mac_addresses"])

def iban_numbers(text: str) -> list:
    return match(text, regex_map["iban_numbers"])

def git_repos(text: str) -> list:
    return match_by_regex_search(text, regex_map["git_repos"])