from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from utiliities import makelogger
from selenium import webdriver
import selenium.common.exceptions as selenium_exceptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
import logging
import cloudscraper.captcha.anticaptcha as anticaptcha
import cloudscraper.captcha as captcha
from cloudscraper.cloudflare import Cloudflare
from cloudscraper import CloudScraper
import cloudscraper


class Browser:
    def __init__(self) -> None:
        self.browser = None

    @staticmethod
    def open_chrome(self, extensions=None):
        """description: open google chrome in auto mode with the specified extensions installed
    """
        if extensions is None:
            extensions = []
        chrome_logger = makelogger("chrome_logger", "chrome_logs.log", level=logging.INFO)
        chrome_driver_path = "/usr/bin/chromedriver"
        chrome_options = webdriver.ChromeOptions()
        for extension in extensions:
            try:
                chrome_options.add_extension(extension)
            except:
                if len(extensions) == 0:
                    chrome_logger.info("no extension specified ")
                else:
                    chrome_logger.error("failed to load extension")
        chrome_service = ChromeService(executable_path=chrome_driver_path, port=5678)
        print("finished configuring service")
        chrome_driver = webdriver.Chrome(service=chrome_service, options=chrome_options)

        return chrome_driver

    @staticmethod
    def open_firefox(self, addons=[]) -> webdriver.Firefox:
        """description: open firefox in auto mode with the specified extensions / addons installed"""
        firefox_logger = makelogger("firefox", "firefox_log.log", level=logging.INFO)
        firefox_driver_path = "/usr/bin/geckodriver"
        firefox_options = webdriver.FirefoxOptions()
        firefox_service = FirefoxService(executable_path=firefox_driver_path, port=5678)
        firefox_driver = webdriver.Firefox(service=firefox_service, options=firefox_options)
        # firefox_driver.get()
        for addon in addons:
            try:
                firefox_driver.install_addon(addon)
            except:
                if len(addons) == 0:
                    firefox_logger.info("no addon specified")
                else:
                    firefox_logger.error("failed to load addon")

        return firefox_driver

    def openbrowser_as_new_proc(self, extensions=None, addons=None):
        with ProcessPoolExecutor(max_workers=1) as executor:
            if self.browser == "chrome":
                result = executor.submit(self.open_chrome, extensions)
            elif self.browser == "firefox":
                result = executor.submit(self.open_firefox, addons)
        return result


class BrHandler():
    """ blocked requests handler , determines the reason for the blocking of the request 
    whether it is waf , network firewall , captcha, and so on and sends the request to 
    the necessary handlers"""

    def __init__(self, browser: str, url: str, cookie_jar, headers) -> None:
        self.browser = browser
        self.url = url
        self.session_cookies = cookie_jar
        self.headers = headers

    def solve_cloudflare_V1(self):
        captcha_logger = makelogger("WAF", "waf.log", level=logging.INFO)
        scraper = cloudscraper.create_scraper()
        response = scraper.get(self.url, self.headers,
                               self.session_cookies)  # set the cookies to be the same cookies used in the session
        print(f"Response code from scraper.get(): {response.status_code}")
        captcha_client = Cloudflare(scraper)
        if captcha_client.is_Captcha_Challenge(response):  # if a cloud flare recaptcha is in place
            print("captcha challenge present")
            # captcha_client.captcha_Challenge_Response()
            # captcha_client.Challenge_Response()
            # if cloudflarev1 has been solved
            return True
        else:
            captcha_logger.info(f"no challenge found on url: {self.url}")
            # if not 
            return False

    def M_detect_captcha_challenge(self):
        """custom function developed to manually detect the presence of captcha challenges"""
        return True

    def M_detect_firewall(self):
        """Custom function developed to manually detect the presence of a network firewall"""
        pass

    def M_detect_WAF(self):
        """custom function developed to manually detect the presence of a WAF"""
        pass
