GET_WEATHER_SCHEMA = {
    "description": "Get weather for a city",
    "parameters": {
        "type": "object",
        "properties": {"city": {"type": "string"}},
        "required": ["city"],
    },
}

SEARCH_NEWS_SCHEMA = {
    "description": "Search news headlines for a topic",
    "parameters": {
        "type": "object",
        "properties": {"topic": {"type": "string"}},
        "required": ["topic"],
    },
}


def get_weather(city: str) -> dict:
    return {"city": city, "temperature_c": 22, "condition": "sunny"}


def search_news(topic: str) -> dict:
    return {
        "topic": topic,
        "headlines": [
            "AI agents gain runtime security tooling",
            "New benchmark for agent risk",
        ],
    }
