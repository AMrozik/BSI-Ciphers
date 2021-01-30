"""
A very, very, very simple webscraper.
It "googles" a given phrase and prints a list of 10 first results

sources:
https://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
https://www.crummy.com/software/BeautifulSoup/bs4/doc/


# pip install bs4
"""

__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"


from multiprocessing.pool import ThreadPool
import pprint
import requests
import re
from bs4 import BeautifulSoup


def Scrap(html_response):
    """
    From given response get all links by finding all <a> tags and get href from them

    html_response - should be a list of html classes parsed by BeautifulSoup
    returns list of links
    """
    results = [re.search('\/url\?q\=(.*)\&sa', str(i.find('a')['href'])) for i in html_response]
    links = [i.group(1) for i in results if i != None]
    # pprint.pprint(links)
    return links


if __name__ == '__main__':
    search = "machine learning"

    response = requests.get(f"https://www.google.com/search?q={search}")
    soup = BeautifulSoup(response.text, "html.parser")
    result = soup.find_all(attrs={'class': 'ZINbbc'})

    result1 = result[:len(result)//2]
    result2 = result[len(result)//2:]

    # Initialize pool
    pool = ThreadPool()

    # do scraping asynchronously
    thr1 = pool.apply_async(Scrap, (result1,))
    thr2 = pool.apply_async(Scrap, (result2,))

    # get return value of each thread
    # that's what i couldn't do so simple with threading module
    links1 = thr1.get()
    links2 = thr2.get()

    # concatenate all results to one list and print it
    links = links1 + links2
    pprint.pprint(links)