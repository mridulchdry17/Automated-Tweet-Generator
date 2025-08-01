from flask import Flask, request, jsonify, send_file, redirect, url_for, session
from langgraph.graph import StateGraph, START, END
from typing import TypedDict, Literal, Annotated
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
import operator
from dotenv import load_dotenv
import requests
import secrets
import os

load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For sessions

# X API OAuth 2.0 settings
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = "http://127.0.0.1:5000/callback"  # Update for production
AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.twitter.com/2/oauth2/token"

# Check if required environment variables are set
if not CLIENT_ID:
    print("⚠️  WARNING: CLIENT_ID not found in environment variables")
    print("   Please set CLIENT_ID in your .env file for X OAuth functionality")

if not CLIENT_SECRET:
    print("⚠️  WARNING: CLIENT_SECRET not found in environment variables")
    print("   Please set CLIENT_SECRET in your .env file for X OAuth functionality")

# In-memory storage for user tokens (use database in production)
user_tokens = {}

# Your Grok models (unchanged)
try:
    generator_llm = ChatGroq(model_name="llama-3.1-8b-instant", temperature=2)
    evaluator_llm = ChatGroq(model_name="llama-3.1-8b-instant")
    optimizer_llm = ChatGroq(model_name="llama-3.1-8b-instant")
except Exception as e:
    print(f"⚠️  WARNING: Could not initialize Groq models: {e}")
    print("   Please ensure GROQ_API_KEY is set in your .env file")
    generator_llm = evaluator_llm = optimizer_llm = None

from pydantic import BaseModel, Field

class TweetEvaluation(BaseModel):
    evaluation: Literal['approved', 'needs_improvement'] = Field(..., description="Final Evaluation")
    feedback: str = Field(..., description="Feedback for the tweet.")

structured_evaluator_llm = evaluator_llm.with_structured_output(TweetEvaluation)

class TweetState(TypedDict):
    topic: str
    tweet: str
    evaluation: Literal["approved", "needs_improvement"]
    feedback: str
    iteration: int
    max_iteration: int
    tweet_history: Annotated[list[str], operator.add]
    feedback_history: Annotated[list[str], operator.add]

# Your existing tweet generation logic (unchanged)
def generate_tweet(state: TweetState):
    messages = [
        SystemMessage(content="You are a funny and clever Twitter/X influencer."),
        HumanMessage(content=f"""
Write a short, original, and hilarious tweet on the topic: \"{state['topic']}\".

Rules:
- Do NOT use question-answer format.
- Max 280 characters.
- Use observational humor, irony, sarcasm, or cultural references.
- Think in meme logic, punchlines, or relatable takes.
- Use simple, day to day english
- This is version {state['iteration'] + 1}.
""")
    ]
    response = generator_llm.invoke(messages).content
    return {'tweet': response, 'tweet_history': [response]}

def evaluate_tweet(state: TweetState):
    messages = [
        SystemMessage(content="You are a ruthless, no-laugh-given Twitter critic."),
        HumanMessage(content=f"""
Evaluate the following tweet:

Tweet: \"{state['tweet']}\"

Criteria:
1. Originality – Is it fresh?
2. Humor – Is it funny?
3. Punchiness – Is it short and catchy?
4. Virality – Would people share it?
5. Format – Under 280 characters, no Q&A or setup-punchline.

Auto-reject if:
- It's a question-answer or setup-punchline joke.
- Over 280 characters.
- Ends with weak lines (e.g., "Masterpieces of the auntie-uncle universe").

Respond in structured format:
- evaluation: "approved" or "needs_improvement"
- feedback: One paragraph explaining strengths and weaknesses
""")
    ]
    response = structured_evaluator_llm.invoke(messages)
    return {
        'evaluation': response.evaluation,
        'feedback': response.feedback,
        'feedback_history': [response.feedback]
    }

def optimize_tweet(state: TweetState):
    messages = [
        SystemMessage(content="You punch up tweets for virality and humor."),
        HumanMessage(content=f"""
Improve the tweet based on this feedback:
"{state['feedback']}"

Topic: "{state['topic']}"
Original Tweet: {state['tweet']}

Re-write as a short, viral tweet. Avoid Q&A, under 280 characters.
""")
    ]
    response = optimizer_llm.invoke(messages).content
    iteration = state['iteration'] + 1
    return {'tweet': response, 'iteration': iteration, 'tweet_history': [response]}

def route_evaluation(state: TweetState):
    if state['evaluation'] == 'approved' or state['iteration'] >= state['max_iteration']:
        return 'approved'
    return 'needs_improvement'

def run_workflow(topic: str, max_iteration: int = 5):
    state = {'topic': topic, 'iteration': 1, 'max_iteration': max_iteration}
    graph = StateGraph(TweetState)
    graph.add_node('generate', generate_tweet)
    graph.add_node('evaluate', evaluate_tweet)
    graph.add_node('optimize', optimize_tweet)
    graph.add_edge(START, 'generate')
    graph.add_edge('generate', 'evaluate')
    graph.add_conditional_edges('evaluate', route_evaluation, {'approved': END, 'needs_improvement': 'optimize'})
    graph.add_edge('optimize', 'evaluate')
    workflow = graph.compile()
    return workflow.invoke(state)

# OAuth 2.0 Routes
@app.route('/login')
def login():
    print("🔍 Login route accessed!")
    
    if not CLIENT_ID:
        return jsonify({'error': 'Client ID not set'}), 500

    # Generate a random state for security
    state = secrets.token_urlsafe(16)
    session['state'] = state
    session['user_id'] = secrets.token_urlsafe(16)  # Unique user ID
    
    # Generate PKCE parameters
    code_verifier = secrets.token_urlsafe(32)
    import hashlib
    import base64
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')

    # Store code_verifier in session
    session['code_verifier'] = code_verifier

    # Redirect to X login
    auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'tweet.read tweet.write users.read offline.access',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    auth_url = f"{AUTH_URL}?{'&'.join(f'{k}={v}' for k, v in auth_params.items())}"
    
    print(f"Redirecting to: {auth_url}")
    print(f"State: {state}")
    print(f"Redirect URI: {REDIRECT_URI}")
    print(f"Code challenge: {code_challenge}")
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    print("🔍 Callback received!")
    print(f"URL args: {dict(request.args)}")
    
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    
    saved_state = session.get('state')
    
    print(f"Code: {code}")
    print(f"State: {state}")
    print(f"Saved state: {saved_state}")
    print(f"Error: {error}")
    print(f"Error description: {error_description}")

    if error:
        return jsonify({'error': f'OAuth error: {error}', 'description': error_description}), 400

    if not code or state != saved_state:
        return jsonify({'error': 'Invalid login attempt'}), 400

    # Exchange code for access token
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return jsonify({'error': 'Code verifier not found in session'}), 400
        
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }
    
    try:
        # Use basic auth with client_id and client_secret
        import base64
        credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_credentials}'
        }
        
        print(f"Token data being sent: {token_data}")
        print(f"Headers: {headers}")
        
        response = requests.post(TOKEN_URL, data=token_data, headers=headers)
        print(f"Token response status: {response.status_code}")
        print(f"Token response: {response.text}")
        
        if response.status_code != 200:
            return jsonify({'error': 'Failed to get token', 'details': response.text}), 500

        token_response = response.json()
        user_tokens[session['user_id']] = {
            'access_token': token_response['access_token'],
            'refresh_token': token_response.get('refresh_token')
        }
        return redirect(url_for('tweet_page'))
    except Exception as e:
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 500

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id and user_id in user_tokens:
        del user_tokens[user_id]
    session.clear()
    return redirect(url_for('landing_page'))

@app.route('/')
def landing_page():
    return send_file('index.html')

@app.route('/tweet')
def tweet_page():
    return send_file('tweet.html')

@app.route('/check-auth')
def check_auth():
    user_id = session.get('user_id')
    is_authenticated = user_id is not None and user_id in user_tokens
    return jsonify({'authenticated': is_authenticated})

@app.route('/test-callback')
def test_callback():
    """Test endpoint to verify callback URL is accessible"""
    return jsonify({'message': 'Callback URL is working!', 'timestamp': 'test'})

@app.route('/generate-tweet', methods=['POST'])
def generate_tweet_api():
    data = request.get_json()
    topic = data.get('topic')
    if not topic:
        return jsonify({'error': 'No topic provided'}), 400
    
    # Check if LLM models are available
    if not generator_llm or not evaluator_llm or not optimizer_llm:
        return jsonify({'error': 'AI models not available. Please check your GROQ_API_KEY configuration.'}), 500
    
    try:
        result = run_workflow(topic)
        return jsonify({
            'tweet': result['tweet'],
            'feedback': result.get('feedback', ''),
            'evaluation': result.get('evaluation', '')
        })
    except Exception as e:
        return jsonify({'error': f'Failed to generate tweet: {str(e)}'}), 500

@app.route('/post-tweet', methods=['POST'])
def post_tweet_api():
    data = request.get_json()
    tweet = data.get('tweet')
    user_id = session.get('user_id')

    if not tweet:
        return jsonify({'error': 'No tweet provided'}), 400
    if not user_id or user_id not in user_tokens:
        return jsonify({'error': 'Please log in with X'}), 401

    access_token = user_tokens[user_id]['access_token']
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    payload = {'text': tweet}
    response = requests.post('https://api.twitter.com/2/tweets', json=payload, headers=headers)

    if response.status_code == 201:
        tweet_id = response.json().get('data', {}).get('id')
        return jsonify({'success': True, 'tweet_id': tweet_id})
    return jsonify({'error': 'Failed to post tweet', 'details': response.text}), 500

if __name__ == '__main__':
    app.run(debug=True)