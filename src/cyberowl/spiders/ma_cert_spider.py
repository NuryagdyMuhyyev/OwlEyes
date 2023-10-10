"""
This spider is used to scrape alerts from the following source:
https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html
"""
import scrapy
from items import AlertItem


class MACertSpider(scrapy.Spider):
    """Spider for the MA-CERT website.

    This spider is used to scrape data from the official website of
    Moroccan CERT.

    Attributes:
        name : Name of the spider.
        max_items : The maximum number of items to scrape.
        start_url : The website from which to start crawling.
        block_selector : The CSS/XPATH selector of the block containing the data.
        link_selector : The CSS/XPATH selector of the link of the alert.
        title_selector : The CSS/XPATH selector of the title of the alert.
        date_selector : The CSS/XPATH selector of the date of creation of the alert.
        description_selector : The CSS/XPATH selector of the description of the alert.
    """

    name = "MA-CERT"
    max_items = 10
    start_urls = ["https://www.dgssi.gov.ma/fr/bulletins-securite"]
    block_selector = "//div[contains(@class,'single-blog-content')]"
    link_selector = "descendant-or-self::h3/a/@href"
    date_selector = "descendant-or-self::li/text()[2]"
    title_selector = "descendant-or-self::h3/a/text()"
    description_selector = ("descendant-or-self::p/text()")

    def parse(self, response):
        """
        Parsing the response.
        """
        for idx, bulletin in enumerate(response.xpath(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = bulletin.xpath(self.link_selector).get()
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
