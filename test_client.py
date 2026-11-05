import asyncio
from mcp import Client
from server import server

async def main():

    async with Client(server) as client:
        tools = await client.list_tools()
        print("Available tools:")
        for tool in tools.tools:
            print(f"- {tool.name}: {tool.description}")

        result = await client.call_tool(
            "read_iot_logs", {}
        )

        print("\nIoT logs (synthetic practice data):")
        for item in result.content:
            if item.type == "text":
                print(item.text)

asyncio.run(main())
