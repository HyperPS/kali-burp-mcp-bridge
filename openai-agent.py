#pip install openai-agents
from agents import Agent, MCPServerSse
import asyncio

async def main():
    async with MCPServerSse(
        name="kali-burp",
        params={"url": "http://127.0.0.1:8082/sse"},
    ) as mcp_server:
        agent = Agent(
            name="PenTest Agent",
            instructions="You are an expert penetration tester. Use the available tools to help test targets.",
            mcp_servers=[mcp_server],
        )
        result = await agent.run("Scan 10.10.10.5 for open ports and identify services")
        print(result.final_output)

asyncio.run(main())
