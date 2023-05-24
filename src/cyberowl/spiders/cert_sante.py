"""
This spider is used to scrape alerts from the following source:
https://www.cyberveille-sante.gouv.fr/alertes-et-vulnerabilites
"""
import scrapy
from items import AlertItem


class SanteSpider(scrapy.Spider):
    """Spider for the CERT Santé website.

    This spider is used to scrape data from the official website of CERT Santé.

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

    name = "CERT-SANTE"
    max_items = 10
    start_urls = ["https://www.cyberveille-sante.gouv.fr/alertes-et-vulnerabilites"]
    block_selector = "//table[@class='cols-7 av-table table table-bordered']/tbody/tr"
    title_selector = "descendant-or-self::td[contains(@class,'views-field-title')]/a/text()"
    link_selector = "descendant-or-self::td[contains(@class,'views-field-title')]/a/@href"
    date_selector = "descendant-or-self::td[contains(@class,'timestamp-to-date')]/text()"
    description_selector = ""

    def parse(self, response):
        """
        Parsing the response
        """
        for idx, bulletin in enumerate(response.xpath(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = (
                    bulletin.xpath(self.title_selector).get()
             )
            item["link"] = (
                "https://www.cyberveille-sante.gouv.fr" + bulletin.xpath(self.link_selector).get()
            )
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = "Visit link for details."

            yield item
