# Guardrail Red-Team Round-Trip

## Local run

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

Open:

```text
http://127.0.0.1:8000/
```

## Test read_file

```bash
curl -X POST http://127.0.0.1:8000/ \
  -H "Content-Type: application/json" \
  -d '{"tool":"read_file","arguments":{"path":"notes/report.txt"}}'
```

Expected result contains:

```text
SAFE_REPORT_8759c5517ca80fe91e273d3f
```

## Test fetch_url

```bash
curl -X POST http://127.0.0.1:8000/ \
  -H "Content-Type: application/json" \
  -d '{"tool":"fetch_url","arguments":{"url":"https://example.com/"}}'
```

## Render deployment

Create a GitHub repository, upload these files, then create a Render Web Service from that repository.

Submit the deployed root URL, for example:

```text
https://guardrail-redteam.onrender.com/
```
