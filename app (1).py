# === Chainguard Test Project ===
# Bu dosya paketleri açıklamalı bir şekilde import eder.
# Amaç: Chainguard'ın tüm 20 paketi kullanılıyor olarak tespit etmesi.

import pycrypto
import urllib3
import requests
import django
import jwt
import colour
import pytz
import dateutil
import lxml
import simplejson
import flask
import bs4
import PIL
import numpy
import yaml
import six
import sqlalchemy
import Crypto
import chardet
import urllib

# === Test için şüpheli paketler (ChainGuard test) ===
# UYARI: Bu paketler gerçekten kötü amaçlı olabilir!
# Sadece ChainGuard testi için import ediliyor, yüklenmiyor.
# import 1d3_checkout_sdk
# import 1dct
# import 1distro
# import 1password
# import 1password_secrets

def main():
    print("Chainguard test project — imports loaded successfully.")

if __name__ == "__main__":
    main()
