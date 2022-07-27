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

This is a collection of commonly used regular expressions. The API provides simple function calls to match the strings corresponding to specified patterns.

## Installation

```pip install commonregex-improved```

## Usage

```python
import commonregex-improved as CommonRegex

text = "John, please get that article on www.linkedin.com to me by 5:00PM on Jan 9th 2012. 4:00 would be ideal, actually. If you have any questions, You can reach me at (519)-236-2723x341 or get in touch with my associate at harold.smith@gmail.com"

date_list = CommonRegex.Dates(text)
# ['Jan 9th 2012']
time_list = CommonRegex.Times(text)
# ['5:00PM', '4:00']
url_list = CommonRegex.Links(text)
# ['www.linkedin.com', 'harold.smith@gmail.com']
phone_list = CommonRegex.Phones_with_exts(text)  
# ['(519)-236-2723x341']
email_list = CommonRegex.Emails(text)
# ['harold.smith@gmail.com']
```
