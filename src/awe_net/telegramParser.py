from telethon import TelegramClient
import random
import hashlib
import asyncio
from config.config import TELEGRAM_API_ID, TELEGRAM_HASH, TELEGRAM_PHONE_NUMBER

class TelegramParser(TelegramClient):
    def __init__(self, session_name):
        super().__init__()
        self.session = session_name
        self.api_id = TELEGRAM_API_ID 
        self.api_hash = TELEGRAM_HASH
    
    async def testConn(self):
        # send a message to yourself
        await self.send_message("me", "this is a message from the telethon api")
        

async def main(parser:TelegramParser):
    await parser.testConn()

if __name__ == "__main__":
    parser = TelegramParser("session056")
    with parser:
        parser.loop.run_until_complete(main())


        

