import argparse
from bs4 import BeautifulSoup as BS
from bs4 import Comment
from urllib.request import Request, urlopen


def comment_parser():

    parser = argparse.ArgumentParser(description='Take a user-input URL and extract all comments from the webpage.')
    parser.add_argument('-u', '--URL', dest='URL', required=True, type=str, help='supply a full URL')
    args = parser.parse_args()
    URL = args.URL

    # TODO remove these comments
    # URL that we're going to gather comments from
    # URL = input(f'Enter the webpage URL from which you want to extract comments: ')
    comment_container = []

    # retrieve the page and store it for use with BS, user agent spoofing to avoid some website security features
    webpage_request = Request(url=URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage_html = urlopen(webpage_request).read()

    # extract html using BS
    page_soup = BS(webpage_html, "html.parser")
    comments = page_soup.find_all(string=lambda text: isinstance(text, Comment))

    # put the comments into a list
    for comment in comments:
        comment_container.append(comment)

    print(comment_container)


if __name__ == "__main__":
    comment_parser()
