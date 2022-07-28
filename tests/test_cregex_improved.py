import pytest
import re
import commonregex.commonregex_improved as cregex

# def test_cregex_find_all():
#   text = "John, please get that article on www.linkedin.com to me by 5:00PM on Jan 9th 2012. 4:00 would be ideal, actually. If you have any questions, You can reach me at (519)-236-2723x341 or get in touch with my associate at harold.smith@gmail.com"
#   test_data=[]



def test_cregex_dates():
    test_data = ["3-23-17",
		"3.23.17",
		"03.23.17",
		"March 23th, 2017",
		"Mar 23th 2017",
		"Mar. 23th, 2017",
		"23 Mar 2017",]

    for test_string in test_data:
        assert cregex.dates(test_string) == [test_string], "Dates regex failed on: " + test_string

def test_cregex_times():
    test_data = ["09:45",
		"9:45",
		"23:45",
		"9:00am",
		"9am",
		"9:00 A.M.",
		"9:00 pm",]

    for test_string in test_data:
        assert cregex.times(test_string) == [test_string], "Times regex failed on: " + test_string

def test_cregex_phones():
    test_data = ["12345678900",
		"1234567890",
		"+1 234 567 8900",
		"234-567-8900",
		"1-234-567-8900",
		"1.234.567.8900",
		"5678900",
		"567-8900",
		"(003) 555-1212",
		"+41 22 730 5989",
		"+442345678900"]

    for test_string in test_data:
        assert cregex.phones(test_string) == [test_string], "Phones regex failed on: " + test_string

def test_cregex_phones_with_exts():
    test_data = ["(523)222-8888 ext 527",
		"(523)222-8888x623",
		"(523)222-8888 x623",
		"(523)222-8888 x 623",
		"(523)222-8888EXT623",
		"523-222-8888EXT623",
		"(523) 222-8888 x 623",]

    for test_string in test_data:
        assert cregex.phones_with_exts(test_string) == [test_string], "Phones with exts regex failed on: " + test_string

def test_cregex_links():
    test_data = ["http://www.google.com",
        "https://www.google.com",
        "www.google.com",
        "http://www.google.com/search?q=python",
        "https://www.google.com/search?q=python",
        "www.google.com/search?q=python",
        "http://www.google.com/search?q=python&hl=en",
        "https://www.google.com/search?q=python&hl=en",
        "www.google.com/search?q=python&hl=en",
        "http://www.google.com/search?q=python&hl=en&tbm=nws",
        "https://www.google.com/search?q=python&hl=en&tbm=nws",
        "www.google.com/search?q=python&hl=en&tbm=nws",
        "http://www.google.com/search?q=python&hl=en&tbm=nws&tbs=qdr:d",
        "https://www.google.com/search?q=python&hl=en&tbm=nws&tbs=qdr:d",
        "www.google.com/search?q=python&hl=en&tbm=nws&tbs=qdr:d",
        "http://www.google.com/search?q=python&hl=en&tbm=nws&tbs=qdr:d&tbs=qdr:w",
        "https://www.google.com/search?q=python&hl=en&tbm=nws&tbs=qdr:d&tbs=qdr:w",
        "www.google.com/search?q=python&hl=en&tbm=nws&tbs=qdr:d&tbs=qdr:w",
        "http://www.google.com/search?q=python&hl=en&t",
        "www.google.com",
		"http://www.google.com",
		"www.google.com/?query=dog",
		"sub.example.com",
		"http://www.google.com/%&#/?q=dog",
		"google.com",]
    
    for test_string in test_data:
        assert cregex.links(test_string) == [test_string], "Links regex failed on: " + test_string

def test_cregex_emails():
    test_data = ["john.smith@gmail.com",
		"john_smith@gmail.com",
		"john@example.net",
		"John@example.net",
        "jane@example.gov.us"]

    failing_tests = ["john.smith@gmail..com"]

    for test_string in test_data:
        assert cregex.emails(test_string) == [test_string], "Emails regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.emails(test_string) != [test_string], "These should not be matched " + test_string

def test_cregex_ipv4s():
    test_data = ["127.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"192.30.253.113",
		"216.58.194.46"]
    
    for test_string in test_data:
        assert cregex.ipv4s(test_string) == [test_string], "IPv4s regex failed on: " + test_string

def test_cregex_ipv6s():
    test_data = ["fe80:0000:0000:0000:0204:61ff:fe9d:f156",
		"fe80:0:0:0:204:61ff:fe9d:f156",
		"fe80::204:61ff:fe9d:f156",
		"fe80:0000:0000:0000:0204:61ff:254.157.241.86",
		"fe80:0:0:0:0204:61ff:254.157.241.86",
		"::1"]

    for test_string in test_data:
        assert cregex.ipv6s(test_string) == [test_string], "IPv6s regex failed on: " + test_string

def test_cregex_ips():
    test_data = ["127.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"192.30.253.113",
		"216.58.194.46",
		"fe80:0000:0000:0000:0204:61ff:fe9d:f156",
		"fe80:0:0:0:204:61ff:fe9d:f156",
		"fe80::204:61ff:fe9d:f156",
		"fe80:0000:0000:0000:0204:61ff:254.157.241.86",
		"fe80:0:0:0:0204:61ff:254.157.241.86",
		"::1"]

    for test_string in test_data:
        assert cregex.ips(test_string) == [test_string], "IPs regex failed on: " + test_string

def test_cregex_not_ports():
    test_data = ["1024",
		"2121",
		"8080",
		"12345",
		"55555",
		"65535"]

    failing_tests = ["21",
		"80",
		"1023",
		"65536"]

    for test_string in test_data:
        assert cregex.not_known_ports(test_string) == [test_string], "Not ports regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.not_known_ports(test_string) != [test_string], "This is a well known port " + test_string

def test_cregex_prices():
    test_data = ["$1.23",
		"$1",
		"$1,000",
		"$10,000.00"]

    failing_tests = ["$1,10,0",
		"$100.000"]

    for test_string in test_data:
        assert cregex.prices(test_string) == [test_string], "Prices regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.prices(test_string) != [test_string], "This is not a price " + test_string

def test_cregex_hex_colors():
    test_data = ["#000000",
        "#FFFFFF",
        "#FF0000",
        "#00FF00",
        "#0000FF",
        "#FFFF00",
        "#FF00FF",
        "#00FFFF",
        "#000000FF",
        "#FFFFFFFF"]

    failing_tests = ["#000000FFF",
        "#FFFFFFFFF"]

    for test_string in test_data:
        assert cregex.hex_colors(test_string) == [test_string], "Hex colors regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.hex_colors(test_string) != [test_string], "This is not a hex color " + test_string

def test_cregex_credit_cards():
    test_data = ["0000-0000-0000-0000",
		"0123456789012345",
		"0000 0000 0000 0000",
		"012345678901234"]

    for test_string in test_data:
        assert cregex.credit_cards(test_string) == [test_string], "Credit cards regex failed on: " + test_string

def test_cregex_visa_cards():
    test_data=["4111 1111 1111 1111",
		"4222 2222 2222 2222"]

    failing_tests = ["5500 0000 0000 0004",
		"3400 0000 0000 009",
		"3000 0000 0000 04"]

    for test_string in test_data:
        assert cregex.visa_cards(test_string) == [test_string], "Visa cards regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.visa_cards(test_string) != [test_string], "This is not a visa card " + test_string


def test_cregex_master_cards():
    test_data=["5500 0000 0000 0004",
		"5500 3334 0000 1234"]

    failing_tests = ["4111 1111 1111 1111",
		"4222 2222 2222 2222",
		"3400 0000 0000 009",
		"3000 0000 0000 04"]

    for test_string in test_data:
        assert cregex.master_cards(test_string) == [test_string], "Master cards regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.master_cards(test_string) != [test_string], "This is not a master card " + test_string

def test_cregex_btc_address():
    test_data = ["1LgqButDNV2rVHe9DATt6WqD8tKZEKvaK2",
		"19P6EYhu6kZzRy9Au4wRRZVE8RemrxPbZP",
		"1bones8KbQge9euDn523z5wVhwkTP3uc1",
		"1Bow5EMqtDGV5n5xZVgdpRPJiiDK6XSjiC"]

    failing_tests = ["2LgqButDNV2rVHe9DATt6WqD8tKZEKvaK2",
		"19Ry9Au4wRRZVE8RemrxPbZP",
		"1bones8KbQge9euDn523z5wVhwkTP3uc12939",
		"1Bow5EMqtDGV5n5xZVgdpR"]

    for test_string in test_data:
        assert cregex.btc_address(test_string) == [test_string], "BTC address regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.btc_address(test_string) != [test_string], "This is not a BTC address " + test_string

def test_cregex_street_addresses():
    test_data = ["101 main st.",
		"504 parkwood drive",
		"3 elm boulevard",
		"500 elm street "]

    failing_tests = ["101 main straight"]

    for test_string in test_data:
        assert cregex.street_addresses(test_string) == [test_string], "Street addresses regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.street_addresses(test_string) != [test_string], "This is not a street address " + test_string

def test_cregex_zip_codes():
    test_data = ["02540",
		"02540-4119"]

    failing_tests = ["10001-1234-5678-9012-3456-7890-1234",
        "101 main straight",
		"123456"]

    for test_string in test_data:
        assert cregex.zip_codes(test_string) == [test_string], "Zip codes regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.zip_codes(test_string) != [test_string], "This is not a zip code " + test_string

def test_cregex_po_boxes():
    test_data = ["PO Box 123456",
		"p.o. box 234234"]

    failing_tests = ["PO Box 1234-5678-9012-3456-7890-1234"]

    for test_string in test_data:
        assert cregex.po_boxes(test_string) == [test_string], "PO boxes regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.po_boxes(test_string) != [test_string], "This is not a PO box " + test_string

def test_cregex_ssns():
    test_data = ["000-00-0000",
		"111-11-1111",
		"222-22-2222",
		"123-45-6789"]

    failing_tests = ["123-45-6789-1234",
        "1234567891234",
        "123-45-6789-1234",
        "1234567891234"]

    for test_string in test_data:
        assert cregex.ssn_numbers(test_string) == [test_string], "SSNs regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.ssn_numbers(test_string) != [test_string], "This is not an SSN " + test_string

def test_cregex_md5_hashes():
    test_data = ["b5ab01fad5a008d436f76aafc896f9c6",
		"00000000000000000000000000000000",
		"fffFFFfFFfFFFfFFFFfFfFfffffFfFFF"]

    failing_tests = ["0cc175b9c0f1b6a831c399e2697723-1234",
        "d41d8cd98f00b204e9800998ecf8427e-1234",
        "900150983cd24fb0d6963f7d28e17f72-1234",
        "f96b697d7cb9dd08c81209bcf0aaf94f-1234",
        "b5ab01fad5a008d436f76aafc896f9c600000000",
		"",
		"7TS5x1trQs652k4AZ3hJE83YCvJRy0U8",
		"b5ab01fad5a008-436f76aafc896f9c6"]

    for test_string in test_data:
        assert cregex.md5_hashes(test_string) == [test_string], "MD5 hashes regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.md5_hashes(test_string) != [test_string], "This is not an MD5 hash " + test_string

def test_cregex_sha1_hashes():
    test_data = ["da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "0000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffff",
        "b5ab01fad5a008d436f76aafc896f9c6abcd1234",
		"0000000000000000000000000000000000000000",
		"fffFFFfFFfFFFfFFFFfFfFfffffFfFFFffffFFFF"]

    failing_tests = ["0cc175b9c0f1b6a831c399e2697723-1234",
        "d41d8cd98f00b204e9800998ecf8427e-1234",
        "900150983cd24fb0d6963f7d28e17f72-1234",
        "f96b697d7cb9dd08c81209bcf0aaf94f-1234",
        "b5ab01fad5a008d436f76aafc896f9c600000000202020202020202020202020",
		"",
		"7TS5x1trQs652k4AZ3hJE83YCvJRy0U85x1trQs652k4AZ3hJE83YCvJRy0U8asd",
		"b5ab01fad5a008-436f76aafc896f9c6-436f76aafc896f9c6-436f76aafc896"
        ]

    for test_string in test_data:
        assert cregex.sha1_hashes(test_string) == [test_string], "SHA1 hashes regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.sha1_hashes(test_string) != [test_string], "This is not an SHA1 hash " + test_string

def test_cregex_sha256_hashes():
    test_data = ["3f4146a1d0b5dac26562ff7dc6248573f4e996cf764a0f517318ff398dcfa792",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffFFFfFFfFFFfFFFFfFfFfffffFfFFFffffFFFFfffffFFFFFffFFffFFffFFff"]

    failing_tests = ["3f4146a1d0b5dac26562ff7dc6248573f4e996cf764a0f517318ff398dcfa7920",
		"",
		"e9iLS075z9HAJlUWg2ZpK5hRxjLeSpIqMKJO67c739VYf7Bj7eR1WjOO82IHcXVd",
		"b5ab01fad5a008-436f76aafc896f9c6-436f76aafc896f9c6-436f76aafc896"
        ]

    for test_string in test_data:
        assert cregex.sha256_hashes(test_string) == [test_string], "SHA256 hashes regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.sha256_hashes(test_string) != [test_string], "This is not an SHA256 hash " + test_string

def test_cregex_isbn13s():
    test_data = ["978-3-16-148410-0",
		"978-1-56619-909-4",
		"133-1-12144-909-9"]

    failing_tests = ["1-56619-909-3",
		"1-33342-100-1",
		"2-33342-362-9"]

    for test_string in test_data:
        assert cregex.isbn13s(test_string) == [test_string], "ISBN13s regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.isbn13s(test_string) != [test_string], "This is not an ISBN13 " + test_string

def test_cregex_isbn10s():
    test_data = ["3-16-148410-0",
        "1-56619-909-4",
        "1-33342-100-1"]

    failing_tests = ["978-3-16-148410-0",
		"978-1-56619-909-4",
		"133-1-12144-909-9"]

    for test_string in test_data:
        assert cregex.isbn10s(test_string) == [test_string], "ISBN10s regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.isbn10s(test_string) != [test_string], "This is not an ISBN10 " + test_string

def test_cregex_mac_addresses():
    test_data = ["f8:2f:a4:fe:76:d2",
		"F8:2F:A4:FE:76:D2",
		"3D-F2-C9-A6-B3-4F"]

    failing_tests = ["3D:F2:C9:A6:B3:4G",
		"f0:2f:P4:Be:96:J5"]

    for test_string in test_data:
        assert cregex.mac_addresses(test_string) == [test_string], "MAC addresses regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.mac_addresses(test_string) != [test_string], "This is not an MAC address " + test_string

def test_cregex_git_repos():
    test_data = ["https://github.com/brootware/commonregex-improved.git",
		"git@github.com:brootware/commonregex-improved.git"]

    failing_tests = ["https://github.com/brootware/commonregex-improved",
		"test@github.com:brootware/commonregex-improved.git"]

    for test_string in test_data:
        assert cregex.git_repos(test_string) == [test_string], "Git repos regex failed on: " + test_string

    for test_string in failing_tests:
        assert cregex.git_repos(test_string) != [test_string], "This is not a Git repo " + test_string

def test_cregex_base_64():
    test_data = ["UEBzc3cwcmRAMTIz",
    "VGhpc0lTQVNFY3JldHBhc3N3b3Jk",
    "aHR0cHM6Ly9naXRodWIuY29tL2Jyb290d2FyZS9jb21tb25yZWdleC1pbXByb3ZlZC5naXQ=",
    "QVBJX1RPS0VO", 
    "UzNjcjN0UGFzc3dvcmQ=", 
    "U3VwM3JTM2NyZXRQQHNzd29yZA=="]

    for test_string in test_data:
        assert cregex.base_64(test_string) == [test_string], "Base 64 regex failed on: " + test_string