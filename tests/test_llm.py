import urllib.request
import json

prompt = '''Fix this code to prevent SQL injection. Replace string concatenation with parameterized queries.

VULNERABLE CODE:
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)

Return ONLY the fixed code, no explanations:'''

payload = {
    'model': 'qwen/qwen3.5-9b',
    'messages': [{'role': 'user', 'content': prompt}],
    'temperature': 0.1,
    'max_tokens': 2000
}

try:
    req = urllib.request.Request(
        'http://127.0.0.1:1234/v1/chat/completions',
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.loads(response.read().decode('utf-8'))
        print('LLM Response status:', 'Success' if 'choices' in result else 'Failed')
        if 'choices' in result:
            fixed = result['choices'][0]['message']['content'].strip()
            print('Fixed code:', repr(fixed))
            print('Fixed code readable:')
            print(fixed)
        else:
            print('Full response:', result)
except Exception as e:
    print('LLM Error:', str(e))