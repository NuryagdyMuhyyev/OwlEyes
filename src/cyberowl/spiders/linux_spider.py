"""
This spider is used to scrape alerts from the following source:
https://www.linux.org/forums/linux-security-announcements-automated.14/
"""
import scrapy
from items import AlertItem


class LinuxSpider(scrapy.Spider):
    """Spider for the Linux.org website.

    This spider is used to scrape data from the official website of
    Linux.org.

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

    name = "LINUX-SEC"
    max_items = 10
    start_urls = ["https://www.linux.org/forums/linux-security-announcements-automated.14/"]
    block_selector = "//div[starts-with(@class,'structItem structItem--thread')]"
    link_selector = "descendant-or-self::div[@class='structItem-title']/a[2]/@href"
    date_selector = (
        "descendant-or-self::time[@class='structItem-latestDate u-dt']/@data-date-string"
    )
    title_selector = "descendant-or-self::div[@class='structItem-title']/a[2]/text()"
    description_selector = ""
    custom_settings = {
        'ROBOTSTXT_OBEY': False
    }

    def parse(self, response):
        """
        Parsing the response
        """
        for idx, bulletin in enumerate(response.xpath(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = (
                "https://www.linux.org" + bulletin.xpath(self.link_selector).get()
            )
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = "Visit link for details."

            yield item
