import asyncio
import websockets

# Maintain a list of connected clients
connected_clients = set()

async def handle_client(websocket, path):
    # Add the client to the set of connected clients
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            # Broadcast the message to all connected clients
            for client in connected_clients:
                await client.send(message)
    except websockets.exceptions.ConnectionClosedError:
        pass
    finally:
        # Remove the client from the set when they disconnect
        connected_clients.remove(websocket)

start_server = websockets.serve(handle_client, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
