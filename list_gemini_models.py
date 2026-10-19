import os

from google import genai


def main() -> None:
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set.")

    client = genai.Client(api_key=api_key)

    print("Models supporting generateContent:\n")

    for model in client.models.list():
        actions = model.supported_actions or []

        if "generateContent" in actions:
            print(f"Model ID: {model.name}")
            print(f"Display name: {model.display_name}")
            print(f"Supported actions: {actions}")
            print("-" * 50)


if __name__ == "__main__":
    main()