"""Phase 7 Step 1: Verify OpenAI API key and find working model."""
import os
import sys
import json

def try_model(client, model_name):
    """Try a single completion call. Return (success, response_text, error)."""
    try:
        resp = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": "Reply with exactly: ADVISORYOPS_API_OK"}],
            max_tokens=20,
            temperature=0,
        )
        text = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        return True, text, tokens, None
    except Exception as e:
        return False, None, 0, str(e)


def main():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set")
        sys.exit(1)
    print(f"API key found: {api_key[:8]}...{api_key[-4:]}")

    try:
        from openai import OpenAI
    except ImportError:
        print("ERROR: openai package not installed. Run: pip install openai")
        sys.exit(1)

    client = OpenAI(api_key=api_key)

    candidates = ["gpt-4o-mini", "gpt-4.1-mini", "gpt-4.1-nano", "gpt-4o"]
    working_model = None

    for model in candidates:
        print(f"\nTrying model: {model} ...", end=" ", flush=True)
        ok, text, tokens, err = try_model(client, model)
        if ok:
            print(f"OK")
            print(f"  Response: {text!r}")
            print(f"  Tokens used: {tokens}")
            working_model = model
            break
        else:
            print(f"FAILED")
            print(f"  Error: {err[:120]}")

    if not working_model:
        print("\nERROR: No working model found from candidates:", candidates)
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"WORKING MODEL: {working_model}")
    print(f"{'='*50}")

    # Save to a small JSON file so other scripts can read it
    result = {"working_model": working_model}
    import pathlib
    pathlib.Path("outputs/phase7_validation").mkdir(parents=True, exist_ok=True)
    with open("outputs/phase7_validation/working_model.json", "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to outputs/phase7_validation/working_model.json")
    return working_model


if __name__ == "__main__":
    main()
