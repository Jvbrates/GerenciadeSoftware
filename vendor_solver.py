import csv
from functools import cache


@cache
def vendor_solver(mac_prefix: str) -> str:
    mac_prefix = mac_prefix.upper()
    print("Without cache")
    with open('mac-vendors-export.csv', mode='r') as infile:
        reader = csv.reader(infile)
        for row in reader:
            if mac_prefix == row[0]:
                return row[1]
        return "Unknow"


