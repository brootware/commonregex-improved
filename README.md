<br><br>

<h1 align="center">CommonRegex Improved</h1>

<p align="center">
  <a href="/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"/></a>
  <img alt="PyPI - Downloads" src="https://pepy.tech/badge/pyredactkit/month">
   <!-- <img alt="PyPI - Downloads" src="https://pepy.tech/badge/pyredactkit"> -->
   <a href="https://twitter.com/brootware"><img src="https://img.shields.io/twitter/follow/brootware?style=social" alt="Twitter Follow"></a>
   <!-- <img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/commonregex-improved"> <img alt="PyPI" src="https://img.shields.io/pypi/v/commonregex-improved"> -->
   <!-- <a href="https://sonarcloud.io/summary/new_code?id=brootware_PyRedactKit"><img src="https://sonarcloud.io/api/project_badges/measure?project=brootware_PyRedactKit&metric=alert_status" alt="reliability rating"></a> -->
   <img alt="GitHub Workflow Status" src="https://img.shields.io/github/workflow/status/brootware/pyredactkit/CI?label=CI&branch=dev">
</p>

<p align="center">
  An improved version of commonly used regular expressions in Python
</p>

<br><br>

> Inspired by and improved upon [CommonRegex](https://github.com/madisonmay/CommonRegex)

This is a collection of commonly used regular expressions. This library provides a simple API interface to match the strings corresponding to specified patterns.

## Installation

```pip install --upgrade commonregex-improved```

## Usage

```python
import commonregex as CommonRegex

text = "John, please get that article on www.linkedin.com to me by 5:00PM on Jan 9th 2012. 4:00 would be ideal, actually. If you have any questions, You can reach me at (519)-236-2723x341 or get in touch with my associate at harold.smith@gmail.com"

date_list = CommonRegex.dates(text)
# ['Jan 9th 2012']
time_list = CommonRegex.times(text)
# ['5:00PM', '4:00']
url_list = CommonRegex.links(text)
# ['www.linkedin.com', 'harold.smith@gmail.com']
phone_list = CommonRegex.phones_with_exts(text)  
# ['(519)-236-2723x341']
email_list = CommonRegex.emails(text)
# ['harold.smith@gmail.com']
identify_all = CommonRegex.find_all(text)
# Do note that the regexes might clash for this find_all function
# ['Jan 9th 2012', '5:00', '(519)-236-2723', '(519)-236-2723x341', 'harold.smith@gmail.com', 'www.linkedin.com']
```

## ⚔️ Performance benchmark

[CommonRegex](https://github.com/madisonmay/CommonRegex) is awesome!

So why re-implement the popular original commonregex project? The API calls to each of the regular expressions are really slow.

It takes 12 seconds for a total of 2999 calls to Dates function in the original version of CommonRegex. While the improved version of CommonRegex with the same number of calls merely takes 2 seconds.

![improved](./benchmark/benchmark.png)

You can find more detailed results about [original](./benchmark/original_cregex_result.pdf) and [improved](./benchmark/cregex_improved_result.pdf) versions.

## Supported methods
