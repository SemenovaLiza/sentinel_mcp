import os
import asyncio
from mcp_server.servers.manager import manager_server
from servers.security import security_server
from dotenv import load_dotenv

load_dotenv()


MANAGER_PORT = os.getenv('MANAGER_PORT')
SECURITY_PORT = os.getenv('SECURITY_PORT')


async def server():
    await asyncio.gather(
        security_server.run_async(transport="sse", host="0.0.0.0", port=int(SECURITY_PORT)),
        manager_server.run_async(transport="sse", host="0.0.0.0", port=int(MANAGER_PORT)),
    )

asyncio.run(server())
